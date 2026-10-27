// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <getopt.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "abi.h"
#include "backend.h"
#include "log.h"
static volatile sig_atomic_t stopping;
static bool controller_stop;
static int control_fd=-1;
static void stop_handler(int sig) {stopping=1;}
#include "retprobe_capacity.h"

static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static const char *schemes[]={"fentry","kprobe","contention","fork","tracepoint","raw"};
static const char *objects[]={"cgroup","mmap","fork"};
static const char *collects[]={"count","state","stack"};
static const char *timeouts[]={"none","poll","timer"};
static const char *counter_names[]={
 "total_start","total_acquire","total_end","match_start","match_acquire","match_end",
 "state_errors","stack_errors","pair_errors","timer_armed","timer_cancelled",
 "timer_fired","timer_errors","ring_sent","ring_dropped","aborted",
 "total_read_start","total_write_start","total_read_return","total_write_return",
 "total_read_release","total_write_release","total_downgrade",
 "match_read_start","match_write_start","match_read_acquire","match_write_acquire",
 "match_read_release","match_write_release","match_read_failed","match_write_failed",
 "match_downgrade","mm_duplicate","mm_aborted","mm_return_old","mm_release_old","stack_collisions",
 "stack_capacity_errors"
};
_Static_assert(sizeof(counter_names)/sizeof(counter_names[0])==COUNTER_MAX,"counter names must match BPF layout");
struct options {
    const char *mode,*object;
    bool observe;int scheme,collect,timeout,target,rw;
    uint64_t threshold_ns;double duration;unsigned poll_ms;
};
struct live_cache;
struct live_saved { struct event event;bool timer; };
struct observer {
    struct bpf_object *object;struct config *cfg;size_t cfg_size;
    struct bpf_link *links[32];unsigned link_count;
    const char *attached[32];struct ring_buffer *ring;
    uint64_t counters[COUNTER_MAX],events_total;
    struct event saved_events[256];unsigned saved_count;
    uint64_t owned_count,state_count,inflight_count,timer_count;
    uint64_t stack_count;int maps_created,cleanup_error;
    unsigned ret_begin,ret_end;
    int target,scheme,timeout,collect;uint64_t threshold_ns;
    struct live_cache *live_seen;uint64_t live_reports,live_poll_errors;
    uint64_t live_dedup_evictions,live_lookup_probes,scan_batch_calls,scan_scalar_calls,scan_fallbacks;
    int scan_batch_support;
    uint64_t mmap_reaped,mmap_reaped_aborted,mmap_cleanup_errors;
    int64_t boot_offset_ns;bool proc_clock_ready;
    bool stack_warning_emitted;
    struct live_saved live_saved[256];unsigned live_saved_count;
};
static int quiet(enum libbpf_print_level level,const char *fmt,va_list args) {
    return level==LIBBPF_DEBUG ? 0 : log_vline(fmt,args);
}
static void quote(const char *s) {
    putchar('"');for(;*s;s++) {
        unsigned char c=*s;
        if(c=='"' || c=='\\') {putchar('\\');putchar(c);}
        else if(c<32)printf("\\u%04x",c);else putchar(c);
    }putchar('"');
}
static int name_index(const char *s,const char **names,int count) {
    for(int i=0;i<count;i++)if(!strcmp(s,names[i]))return i;return -1;
}
static uint64_t number(const char *s) {
    char *end;errno=0;unsigned long long n=strtoull(s,&end,10);
    if(errno || !*s || *s=='-' || *end || !n) {log_line("Invalid positive integer: %s",s);exit(2);}return n;
}
static void usage(FILE *out) {
    fprintf(out,"Backend: %s\nUsage: observer run [OPTIONS] | inspect [--object FILE]\n",backend.name);
    fputs("  --observe on|off           default: off\n"
          "  --collect count|state|stack default: stack\n"
          "  --timeout none|poll|timer  default: poll; subject to backend capability\n"
          "  --duration SECONDS         omit: run until Ctrl+C; maximum: 86400\n"
          "  --threshold-ns N           default: 100000000 (100 ms)\n"
          "  --poll-ms N                default: 100; range 1..60000\n"
          "  --rw both|write            default: both\n"
          "  --object FILE              next to executable: observer.bpf.o; timer: observer.timer.bpf.o\n"
          "  --help                     show this help\n",out);
}
static int parse(int argc,char **argv,struct options *o,char *object,size_t size) {
    if(argc==2 && (!strcmp(argv[1],"--help") || !strcmp(argv[1],"-h"))) {usage(stdout);exit(0);}
    if(argc<2 || (strcmp(argv[1],"run") && strcmp(argv[1],"inspect")))return EINVAL;
    *o=(struct options){.mode=argv[1],.duration=0,.threshold_ns=100000000ull,.poll_ms=100,.rw=3,
        .collect=COLLECT_STACK,.timeout=TIMEOUT_POLL,
        .target=backend.target,.scheme=backend.scheme};
    ssize_t n=readlink("/proc/self/exe",object,size-1);
    if(n<0 || (size_t)n>=size-1)return EINVAL;
    object[n]=0;char *slash=strrchr(object,'/');if(!slash)return EINVAL;
    if((size_t)(slash-object)+strlen("/observer.bpf.o")+1>size)return ENAMETOOLONG;
    strcpy(slash,"/observer.bpf.o");o->object=object;
    enum {OPT_OBSERVE=1000,OPT_COLLECT,OPT_DURATION,OPT_THRESHOLD,OPT_OBJECT,OPT_RW,OPT_POLL,OPT_TIMEOUT};
    struct option opts[]={
        {"observe",required_argument,0,OPT_OBSERVE},{"collect",required_argument,0,OPT_COLLECT},
        {"timeout",required_argument,0,OPT_TIMEOUT},{"duration",required_argument,0,OPT_DURATION},
        {"threshold-ns",required_argument,0,OPT_THRESHOLD},{"object",required_argument,0,OPT_OBJECT},
        {"rw",required_argument,0,OPT_RW},{"poll-ms",required_argument,0,OPT_POLL},
        {"help",no_argument,0,'h'},{0}};
    optind=2;int c;
    while((c=getopt_long(argc,argv,"h",opts,NULL))!=-1) {
        if(c=='h') {usage(stdout);exit(0);}
        if(!strcmp(o->mode,"inspect") && c!=OPT_OBJECT)return EINVAL;
        switch(c) {
        case OPT_OBSERVE:
            if(strcmp(optarg,"off") && strcmp(optarg,"on"))return EINVAL;
            o->observe=!strcmp(optarg,"on");break;
        case OPT_COLLECT:o->collect=name_index(optarg,collects,3);if(o->collect<0)return EINVAL;break;
        case OPT_TIMEOUT:o->timeout=name_index(optarg,timeouts,3);if(o->timeout<0)return EINVAL;break;
        case OPT_RW:
            if(strcmp(optarg,"both") && strcmp(optarg,"write"))return EINVAL;
            o->rw=!strcmp(optarg,"both") ? 3 : 2;break;
        case OPT_DURATION:{
            char *end;o->duration=strtod(optarg,&end);
            if(*end || !(o->duration>0 && o->duration<=86400))return EINVAL;break;
        }
        case OPT_THRESHOLD:o->threshold_ns=number(optarg);break;
        case OPT_POLL:{
            char *end;errno=0;unsigned long n=strtoul(optarg,&end,10);
            if(errno || !*optarg || *optarg=='-' || *end || !n || n>60000)return EINVAL;
            o->poll_ms=n;break;
        }
        case OPT_OBJECT:o->object=optarg;break;
        default:return EINVAL;
        }
    }
    if(optind!=argc)return EINVAL;
    if(!strcmp(o->mode,"inspect"))return 0;
    if(o->poll_ms>60000)return EINVAL;
    if(o->timeout!=TIMEOUT_NONE && o->collect==COLLECT_COUNT)return EINVAL;
    if(o->timeout==TIMEOUT_TIMER && !backend.supports_timer)return ENOTSUP;
    if(o->timeout==TIMEOUT_TIMER && o->object==object) {
        if((size_t)(slash-object)+strlen("/observer.timer.bpf.o")+1>size)return ENAMETOOLONG;
        strcpy(slash,"/observer.timer.bpf.o");
    }
    return 0;
}
static uint64_t symbol(const char *name) {
    FILE *f=fopen("/proc/kallsyms","r");if(!f)return 0;
    char line[512],nm[256],type;unsigned long long addr;
    while(fgets(line,sizeof(line),f))if(sscanf(line,"%llx %c %255s",&addr,&type,nm)==3 && !strcmp(nm,name)) {fclose(f);return addr;}
    fclose(f);return 0;
}
static void live_event(struct observer *b,const struct event *e,const char *source);
static int event_consume(void *ctx,void *data,size_t size) {
    struct observer *b=ctx;if(size!=sizeof(struct event))return 0;
    b->events_total++;if(b->saved_count<256)b->saved_events[b->saved_count++]=*(struct event *)data;
    if(b->timeout==TIMEOUT_TIMER)live_event(b,data,"timer");return 0;
}
static int map_fd(struct observer *b,const char *name) {
    struct bpf_map *m=bpf_object__find_map_by_name(b->object,name);return m ? bpf_map__fd(m) : -1;
}
static uint64_t map_count(struct observer *b,const char *name) {
    int fd=map_fd(b,name);if(fd<0)return 0;
    struct bpf_map *m=bpf_object__find_map_by_name(b->object,name);
    unsigned char key[64],next[64];uint64_t n=0;
    if(bpf_map__key_size(m)>sizeof(key))return UINT64_MAX;
    int rc=bpf_map_get_next_key(fd,NULL,next);
    while(!rc && n<=bpf_map__max_entries(m)) {n++;memcpy(key,next,sizeof(key));rc=bpf_map_get_next_key(fd,key,next);}
    return n;
}
// Read scalar and structured per-CPU counter layouts.
static int read_counters(struct observer *b,uint64_t *out) {
    if(!b->object)return 0;
    struct bpf_map *map=bpf_object__find_map_by_name(b->object,"counters");
    if(!map)return EPROTO;
    int cpus=libbpf_num_possible_cpus();if(cpus<=0)return EIO;
    size_t width=bpf_map__value_size(map),stride=(width+7)&~7u;
    if(width!=sizeof(struct counter_values) && width!=sizeof(struct counter_values)+8 && width!=sizeof(__u64))return EPROTO;
    unsigned char *values=calloc((size_t)cpus,stride);if(!values)return ENOMEM;
    __u32 entries=width==sizeof(__u64) ? bpf_map__max_entries(map) : 1;
    if(entries>COUNTER_MAX+1) {free(values);return EPROTO;}
    memset(out,0,sizeof(uint64_t)*COUNTER_MAX);
    int error=0;
    for(__u32 key=0;key<entries;key++) {
        if(bpf_map_lookup_elem(bpf_map__fd(map),&key,values)) {error=errno;break;}
        for(int cpu=0;cpu<cpus;cpu++) {
            __u64 *v=(void *)(values+(size_t)cpu*stride);
            // Previous layouts had a removed identity counter before capacity errors.
            if(width==sizeof(__u64)) {
                if(key<STACK_CAPACITY_ERRORS)out[key]+=*v;
                else if(key==STACK_CAPACITY_ERRORS+1)out[STACK_CAPACITY_ERRORS]+=*v;
            } else {
                for(unsigned k=0;k<STACK_CAPACITY_ERRORS;k++)out[k]+=v[k];
                out[STACK_CAPACITY_ERRORS]+=v[width/sizeof(__u64)-1];
            }
        }
    }
    free(values);
    if(b->target==OBJECT_MMAP) {
        out[TOTAL_START]=out[TOTAL_READ_START]+out[TOTAL_WRITE_START];
        out[TOTAL_ACQUIRE]=out[TOTAL_READ_RETURN]+out[TOTAL_WRITE_RETURN];
        out[TOTAL_END]=out[TOTAL_READ_RELEASE]+out[TOTAL_WRITE_RELEASE];
        out[MATCH_START]=out[MATCH_READ_START]+out[MATCH_WRITE_START];
        out[MATCH_ACQUIRE]=out[MATCH_READ_ACQUIRE]+out[MATCH_WRITE_ACQUIRE];
        out[MATCH_END]=out[MATCH_READ_RELEASE]+out[MATCH_WRITE_RELEASE];
    }
    return error;
}
static unsigned stack_capacity(struct observer *b) {
    unsigned capacity=0;if(!b->object)return 0;
    const char *names[]={"stacks","stack_overflow"};
    for(unsigned i=0;i<2;i++) {
        struct bpf_map *m=bpf_object__find_map_by_name(b->object,names[i]);
        if(m)capacity+=bpf_map__max_entries(m);
    }
    return capacity;
}
static void stack_health(struct observer *b) {
    if(!b->cfg || b->collect!=COLLECT_STACK || b->stack_warning_emitted)return;
    uint64_t counters[COUNTER_MAX]={0};
    if(read_counters(b,counters) || !counters[STACK_ERRORS])return;
    b->stack_warning_emitted=true;
    log_line("STACK_WARNING target=%s errors=%llu capacity_errors=%llu entries=%llu capacity=%u existing_stack_ids_preserved=true",
        objects[b->target],(unsigned long long)counters[STACK_ERRORS],
        (unsigned long long)counters[STACK_CAPACITY_ERRORS],
        (unsigned long long)(map_count(b,"stacks")+map_count(b,"stack_overflow")),stack_capacity(b));
}
#include "mmap_cleanup.h"
#include "live.h"
static int open_observer(struct observer *b,const struct options *o) {
    b->target=o->target;b->scheme=o->scheme;b->timeout=o->timeout;b->threshold_ns=o->threshold_ns;b->collect=o->collect;
    b->ret_begin=b->ret_end=managed_return_count;
    if(!o->observe)return 0;
    struct rlimit limit={RLIM_INFINITY,RLIM_INFINITY};setrlimit(RLIMIT_MEMLOCK,&limit);
    b->object=bpf_object__open_file(o->object,NULL);
    int e=libbpf_get_error(b->object);if(e) {b->object=NULL;return -e;}
    struct config cfg={.threshold_ns=o->threshold_ns,.scheme=o->scheme,.collect=o->collect,
        .object=o->target,.rw=o->rw,.timeout=o->timeout};
    struct stat pid_ns;if(stat("/proc/1/ns/pid",&pid_ns))return errno;
    cfg.pid_ns_dev=pid_ns.st_dev;cfg.pid_ns_ino=pid_ns.st_ino;
    if(backend.lock_symbol) {cfg.target_lock=symbol(backend.lock_symbol);if(!cfg.target_lock)return EACCES;}
    struct bpf_program *p;unsigned program_count=0;
    bpf_object__for_each_program(p,b->object) {
        bool expected=false;
        for(unsigned i=0;i<backend.program_count;i++)if(!strcmp(bpf_program__name(p),backend.programs[i]))expected=true;
        if(!expected)return EPROTO;program_count++;
    }
    if(program_count!=backend.program_count)return EPROTO;
    if(o->timeout==TIMEOUT_TIMER && !bpf_object__find_map_by_name(b->object,
            o->target==OBJECT_MMAP ? "mm_timers" : "timers")) {
        log_line("Timer requires observer.timer.bpf.o; selected object: %s",o->object);
        return ENOTSUP;
    }
    struct bpf_map *m,*bss=NULL;
    bpf_object__for_each_map(m,b->object) {
        const char *n=bpf_map__name(m);size_t len=strlen(n);
        if(len>=4 && !strcmp(n+len-4,".bss"))bss=m;
    }
    if(!bss || bpf_map__value_size(bss)!=sizeof(cfg))return EPROTO;
    e=bpf_map__set_initial_value(bss,&cfg,sizeof(cfg));if(e)return -e;
    e=bpf_object__load(b->object);if(e)return -e;
    bpf_object__for_each_map(m,b->object)if(bpf_map__fd(m)>=0)b->maps_created++;
    size_t pagesize=sysconf(_SC_PAGESIZE);b->cfg_size=(sizeof(cfg)+pagesize-1)/pagesize*pagesize;
    void *mapping=mmap(NULL,b->cfg_size,PROT_READ|PROT_WRITE,MAP_SHARED,bpf_map__fd(bss),0);
    if(mapping==MAP_FAILED)return errno;b->cfg=mapping;
    if(memcmp(b->cfg,&cfg,sizeof(cfg)))return EPROTO;
    if(o->timeout==TIMEOUT_TIMER) {
        b->ring=ring_buffer__new(map_fd(b,"events"),event_consume,b,NULL);if(!b->ring)return errno;
    }
    // Admission stays off until every selected hook has attached.
    bpf_object__for_each_program(p,b->object) {
        struct bpf_link *link=!strncmp(bpf_program__section_name(p),"kretprobe/",10) ? attach_sized_return(p) : bpf_program__attach(p);
        b->ret_end=managed_return_count;
        long err=libbpf_get_error(link);if(!link || err)return err ? -err : (errno ? errno : EIO);
        if(b->link_count>=32) {bpf_link__destroy(link);return E2BIG;}
        b->attached[b->link_count]=bpf_program__name(p);b->links[b->link_count++]=link;
    }
    return 0;
}
static void gate(struct observer *b,bool enabled,bool admit) {
    if(!b->cfg)return;
    __atomic_store_n(&b->cfg->admit,admit,__ATOMIC_SEQ_CST);
    __atomic_store_n(&b->cfg->enabled,enabled,__ATOMIC_SEQ_CST);
}
static int snapshot(struct observer *b) {
    if(!b->object)return 0;
    if(b->ring)ring_buffer__consume(b->ring);
    int error=read_counters(b,b->counters);if(error)return error;
    b->owned_count=map_count(b,"owned");b->state_count=map_count(b,"states");
    b->inflight_count=map_count(b,"inflight");
    b->timer_count=map_count(b,"timers");b->stack_count=map_count(b,"stacks")+map_count(b,"stack_overflow");
    uint64_t mmap_records=map_count(b,"mm_records");
    b->owned_count+=mmap_records;
    if(b->collect!=COLLECT_COUNT)b->state_count+=mmap_records;
    b->counters[MM_ABORTED]+=b->mmap_reaped_aborted;
    b->inflight_count+=map_count(b,"mm_calls");b->timer_count+=map_count(b,"mm_timers");
    return 0;
}
static void detach(struct observer *b) {
    gate(b,false,false);
    for(unsigned i=b->link_count;i;i--) {bpf_link__destroy(b->links[i-1]);b->links[i-1]=NULL;}
}
static void close_observer(struct observer *b) {
    if(b->ring)ring_buffer__free(b->ring);
    if(b->cfg)munmap(b->cfg,b->cfg_size);
    if(b->object)bpf_object__close(b->object);
    free(b->live_seen);
}
static int inspect(const struct options *o) {
    struct bpf_object *obj=bpf_object__open_file(o->object,NULL);int e=libbpf_get_error(obj);
    if(e)return -e;
    printf("{\"bpf_loaded\":false,\"object\":");quote(o->object);printf(",\"programs\":[");
    bool first=true;struct bpf_program *p;bpf_object__for_each_program(p,obj) {
        printf("%s{\"name\":",first ? "" : ",");first=false;quote(bpf_program__name(p));
        printf(",\"section\":");quote(bpf_program__section_name(p));
        printf(",\"type\":%u,\"expected_attach_type\":%u}",bpf_program__type(p),bpf_program__expected_attach_type(p));
    }
    printf("],\"maps\":[");first=true;struct bpf_map *m;bpf_object__for_each_map(m,obj) {
        printf("%s{\"name\":",first ? "" : ",");first=false;quote(bpf_map__name(m));
        printf(",\"type\":%u,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u}",
            bpf_map__type(m),bpf_map__key_size(m),bpf_map__value_size(m),bpf_map__max_entries(m));
    }
    printf("]}\n");bpf_object__close(obj);return 0;
}
static void print_records(struct observer *b) {
    int fd,rc;__u32 key,next;
    printf("\"timeout_events\":[");
    for(unsigned i=0;i<b->saved_count;i++) {
        struct event *e=&b->saved_events[i];
        printf("%s{\"tgid\":%u,\"tid\":%u,\"stage\":%u,\"age_ns\":%llu,\"stack_id\":%d,\"lock_kind\":%u,\"lock_addr\":\"0x%llx\"}",
            i ? "," : "",(__u32)(e->state.id>>32),(__u32)e->state.id,e->state.stage,
            (unsigned long long)(e->now_ns-e->state.start_ns),e->state.stack_id,e->lock_kind,(unsigned long long)e->lock_addr);
    }
    printf("],\"timeout_events_received\":%llu,\"timeout_events_truncated\":%s,",(unsigned long long)b->events_total,b->events_total>b->saved_count ? "true" : "false");
    printf("\"live_events\":[");
    for(unsigned i=0;i<b->live_saved_count;i++) {
        const struct live_saved *s=&b->live_saved[i];const struct event *e=&s->event;
        printf("%s{\"source\":\"%s\",\"tgid\":%u,\"tid\":%u,\"start_ns\":%llu,\"acquired_ns\":%llu,\"age_ns\":%llu,\"stage\":%u,\"stack_id\":%d,\"lock_kind\":%u,\"lock_addr\":\"0x%llx\"}",
            i ? "," : "",s->timer ? "timer" : "poll",(__u32)(e->state.id>>32),(__u32)e->state.id,
            (unsigned long long)e->state.start_ns,(unsigned long long)e->state.acquired_ns,
            (unsigned long long)(e->now_ns-e->state.start_ns),e->state.stage,e->state.stack_id,
            e->lock_kind,(unsigned long long)e->lock_addr);
    }
    printf("],\"live_events_truncated\":%s,",b->live_reports>b->live_saved_count ? "true" : "false");
    printf("\"entry_stacks\":[");unsigned saved=0;
    for(unsigned pass=0;pass<2;pass++) {
    fd=b->object ? map_fd(b,pass ? "stack_overflow" : "stacks") : -1;
    rc=fd>=0 ? bpf_map_get_next_key(fd,NULL,&next) : -1;
    while(!rc && saved<64) {
        __u64 ips[32]={0};if(!bpf_map_lookup_elem(fd,&next,ips)) {
            printf("%s{\"id\":%u,\"ips\":[",saved ? "," : "",next+pass*4096);
            for(unsigned j=0;j<32 && ips[j];j++)printf("%s\"0x%llx\"",j ? "," : "",(unsigned long long)ips[j]);
            printf("]}");saved++;
        }key=next;rc=bpf_map_get_next_key(fd,&key,&next);
    }
    }
    printf("],\"entry_stacks_truncated\":%s,",b->stack_count>saved ? "true" : "false");
    printf("\"unfinished\":[");saved=0;
    for(int pass=0;pass<2;pass++) {
        fd=b->object && (!pass || b->collect!=COLLECT_COUNT) ? map_fd(b,pass ? "mm_records" : "states") : -1;
        unsigned char skey[64]={0},snext[64]={0};rc=fd>=0 ? bpf_map_get_next_key(fd,NULL,snext) : -1;
        while(!rc && saved<64) {
            struct record value={0};
            if(!bpf_map_lookup_elem(fd,snext,&value)) {
                struct record *r=&value;__u32 kind=0;
                if(pass) {struct mmap_key k;memcpy(&k,snext,sizeof(k));kind=k.write ? 2 : 1;}
                __u64 sem;memcpy(&sem,snext+(pass ? 0 : 8),sizeof(sem));
                printf("%s{\"tgid\":%u,\"tid\":%u,\"start_ns\":%llu,\"acquired_ns\":%llu,\"stage\":%u,\"stack_id\":%d,\"lock_kind\":%u,\"lock_addr\":\"0x%llx\"}",
                    saved ? "," : "",(__u32)(r->id>>32),(__u32)r->id,(unsigned long long)r->start_ns,(unsigned long long)r->acquired_ns,r->stage,r->stack_id,kind,(unsigned long long)sem);saved++;
            }memcpy(skey,snext,sizeof(skey));rc=bpf_map_get_next_key(fd,skey,snext);
        }
    }
    printf("],\"unfinished_truncated\":%s,",b->state_count>saved ? "true" : "false");
}
static void output(struct observer *b,const struct options *o,uint64_t elapsed_ns,int error) {
    printf("{\"version\":3,\"mode\":\"run\",\"observe\":%s,\"scheme\":",o->observe ? "true" : "false");
    quote(schemes[o->scheme]);
    printf(",\"target\":");quote(objects[o->target]);
    printf(",\"rw\":");quote(o->rw==3 ? "both" : "write");
    printf(",\"collect\":");quote(collects[o->collect]);
    printf(",\"timeout\":");quote(timeouts[o->timeout]);
    printf(",\"scope\":\"host\"");
    printf(",\"poll_ms\":%u,\"live_reports\":%llu,\"live_poll_errors\":%llu",o->timeout==TIMEOUT_POLL ? o->poll_ms : 0,
        (unsigned long long)b->live_reports,(unsigned long long)b->live_poll_errors);
    printf(",\"live_dedup_evictions\":%llu,\"state_scan_mode\":\"%s\",\"scan_batch_calls\":%llu,\"scan_scalar_calls\":%llu,\"scan_fallbacks\":%llu",
        (unsigned long long)b->live_dedup_evictions,b->scan_batch_support>0 ? "batch" : b->scan_scalar_calls ? "scalar" : "unused",
        (unsigned long long)b->scan_batch_calls,(unsigned long long)b->scan_scalar_calls,(unsigned long long)b->scan_fallbacks);
    printf(",\"stack_capacity\":%u,\"stack_warning_emitted\":%s",stack_capacity(b),b->stack_warning_emitted ? "true" : "false");
    struct bpf_map *events=b->object ? bpf_object__find_map_by_name(b->object,"events") : NULL;
    printf(",\"ring_buffer_bytes\":%u",events && bpf_map__fd(events)>=0 ? bpf_map__max_entries(events) : 0);
    printf(",\"mmap_reaped_records\":%llu,\"mmap_cleanup_errors\":%llu",
        (unsigned long long)b->mmap_reaped,(unsigned long long)b->mmap_cleanup_errors);
    printf(",\"threshold_ns\":%llu,\"error\":%d,\"cleanup_error\":%d,\"elapsed_ns\":%llu,",
        (unsigned long long)o->threshold_ns,error,b->cleanup_error,(unsigned long long)elapsed_ns);
    printf("\"object\":");quote(o->object);
    printf(",\"bpf_loaded\":%s,\"maps_created\":%d,\"attached\":[",b->cfg ? "true" : "false",b->maps_created);
    for(unsigned i=0;i<b->link_count;i++) {if(i)putchar(',');quote(b->attached[i]);}
    printf("],\"counters\":{");
    for(unsigned i=0;i<COUNTER_MAX;i++) {
        if(i)putchar(',');quote(counter_names[i]);printf(":%llu",(unsigned long long)b->counters[i]);
    }
    printf("},\"owned_entries\":%llu,\"state_entries\":%llu,\"inflight_entries\":%llu,\"timer_entries\":%llu,\"stack_entries\":%llu,",
        (unsigned long long)b->owned_count,(unsigned long long)b->state_count,(unsigned long long)b->inflight_count,
        (unsigned long long)b->timer_count,(unsigned long long)b->stack_count);
    print_records(b);print_return_profile(b->ret_begin,b->ret_end);
    printf("\"stop_reason\":\"%s\",\"stopped_by_signal\":%s}\n",
        error ? "error" : stopping ? "signal" : controller_stop ? "controller" : "duration",stopping ? "true" : "false");
}
static int until_ms(uint64_t deadline) {
    if(deadline==UINT64_MAX)return -1;
    uint64_t now=now_ns();if(now>=deadline)return 0;
    uint64_t ms=(deadline-now+999999)/1000000;
    return ms>INT_MAX ? INT_MAX : (int)ms;
}
// Atomically unblock stop signals while sleeping, avoiding a lost-wakeup race.
static int wait_ready(struct pollfd *fds,nfds_t count,int timeout,bool check_stop) {
    sigset_t signals,old;sigemptyset(&signals);
    sigaddset(&signals,SIGINT);sigaddset(&signals,SIGTERM);
    if(sigprocmask(SIG_BLOCK,&signals,&old))return -1;
    struct timespec duration={.tv_sec=timeout>0 ? timeout/1000 : 0,
        .tv_nsec=timeout>0 ? (timeout%1000)*1000000L : 0};
    int rc=check_stop && stopping ? 0 : ppoll(fds,count,timeout<0 ? NULL : &duration,&old);
    int error=errno;
    sigprocmask(SIG_SETMASK,&old,NULL);errno=error;return rc;
}
// The ring epoll fd and controller socket share a single blocking wait.
static int poll_observer(struct observer *b,int timeout,bool watch_control,bool *ready) {
    struct pollfd fds[2];nfds_t count=0;int ring=-1,control=-1;
    if(ready)*ready=false;
    if(b->ring) {ring=(int)count;fds[count++]=(struct pollfd){.fd=ring_buffer__epoll_fd(b->ring),.events=POLLIN};}
    if(watch_control && control_fd>=0) {control=(int)count;fds[count++]=(struct pollfd){.fd=control_fd,.events=POLLIN};}
    int rc=wait_ready(fds,count,timeout,watch_control);
    if(rc<0)return errno==EINTR ? 0 : errno;
    if(control>=0 && fds[control].revents && ready)*ready=true;
    if(ring>=0 && fds[ring].revents) {
        if(fds[ring].revents&(POLLERR|POLLHUP|POLLNVAL))return EIO;
        rc=ring_buffer__consume(b->ring);if(rc<0)return -rc;
    }
    return 0;
}
static bool has_pending(struct observer *b) {
    return b->object && (map_count(b,"owned") || map_count(b,"mm_records"));
}
// The bench controller supplies a private socket, never a workload/PID filter.
// Loading, attachment and export stay outside the ready/go/done window.
static int control_wait(char expected) {
    uint64_t deadline=now_ns()+30000000000ull;
    while(!stopping && now_ns()<deadline) {
        struct pollfd p={.fd=control_fd,.events=POLLIN};
        int rc=wait_ready(&p,1,until_ms(deadline),true);
        if(rc<0) {if(errno==EINTR)continue;return errno;}
        if(rc>0) {char value;if(read(control_fd,&value,1)!=1)return EPIPE;return value==expected ? 0 : EPROTO;}
    }
    return stopping ? EINTR : ETIMEDOUT;
}
int main(int argc,char **argv) {
    struct options o;char object[PATH_MAX];
    int error=parse(argc,argv,&o,object,sizeof(object));
    if(error) {usage(stderr);return 2;}
    libbpf_set_print(quiet);
    if(!strcmp(o.mode,"inspect")) {
        error=inspect(&o);if(error)log_line("inspect: %s",strerror(error));return error ? 1 : 0;
    }
    const char *control=getenv("LOCKBENCH_CONTROL_FD");
    if(control) {
        char *end;errno=0;long fd=strtol(control,&end,10);
        if(errno || !*control || *end || fd<0 || fd>INT_MAX || fcntl(fd,F_GETFD)<0)return 2;
        control_fd=fd;
    }
    signal(SIGINT,stop_handler);signal(SIGTERM,stop_handler);signal(SIGPIPE,SIG_IGN);
    struct observer b={0};uint64_t elapsed_ns=0;
    error=open_observer(&b,&o);if(error)goto done;
    if(control_fd>=0) {
        if(write(control_fd,"R",1)!=1) {error=EPIPE;goto done;}
        error=control_wait('G');if(error)goto done;
    }
    uint64_t t0=now_ns(),deadline=o.duration ? t0+(uint64_t)(o.duration*1e9) : UINT64_MAX;
    gate(&b,true,true);
    if(control_fd>=0 && write(control_fd,"A",1)!=1) {error=EPIPE;goto done;}
    log_line("OBSERVER_READY scope=host backend=%s observe=%s",backend.name,o.observe ? "on" : "off");
    log_line("OBJECT_CONFIG target=%s method=%s collect=%s timeout=%s",objects[o.target],schemes[o.scheme],collects[o.collect],timeouts[o.timeout]);
    fflush(stderr);
    bool scan=b.cfg && o.timeout==TIMEOUT_POLL;
    uint64_t next_scan=scan ? t0+(uint64_t)o.poll_ms*1000000ull : UINT64_MAX;
    uint64_t next_health=b.cfg && o.collect==COLLECT_STACK ? t0+5000000000ull : UINT64_MAX;
    uint64_t next_reap=b.cfg && b.target==OBJECT_MMAP ? t0+5000000000ull : UINT64_MAX;
    while(!stopping && now_ns()<deadline) {
        uint64_t wake=deadline;
        if(next_scan<wake)wake=next_scan;
        if(next_health<wake)wake=next_health;
        if(next_reap<wake)wake=next_reap;
        bool ready=false;
        error=poll_observer(&b,until_ms(wake),true,&ready);if(error)break;
        if(ready) {error=control_wait('D');controller_stop=!error;break;}
        if(stopping)break;
        if(now_ns()>=next_reap) {mmap_reap(&b);next_reap=now_ns()+5000000000ull;}
        if(scan && now_ns()>=next_scan) {
            live_scan(&b);
            next_scan=now_ns()+(uint64_t)o.poll_ms*1000000ull;
        }
        if(now_ns()>=next_health) {
            stack_health(&b);
            next_health=b.stack_warning_emitted ? UINT64_MAX : now_ns()+5000000000ull;
        }
    }
    elapsed_ns=now_ns()-t0;
    gate(&b,true,false);
    mmap_reap(&b);
    uint64_t drain=now_ns()+500000000ull;
    while(now_ns()<drain && has_pending(&b)) {
        int e=poll_observer(&b,10,false,NULL);if(e) {if(!error)error=e;break;}
    }
    gate(&b,false,false);
    mmap_reap(&b);
    stack_health(&b);
    {int e=snapshot(&b);if(!error)error=e;}
    {int e=snapshot_return_profile();if(!error)error=e;}
done:
    detach(&b);
    b.cleanup_error=remove_managed_returns();
    if(error)log_line("lockbench: %s (%d)",strerror(error),error);
    output(&b,&o,elapsed_ns,error);
    close_observer(&b);live_symbols_free();
    return error || b.cleanup_error ? 1 : 0;
}
