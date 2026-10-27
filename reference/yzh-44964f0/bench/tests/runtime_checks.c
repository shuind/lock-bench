// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <bpf/bpf.h>
static int forced_batch_error;
static int delete_batch_candidate;
static int checked_lookup_batch(int fd,void *in,void *out,void *keys,void *values,
        __u32 *count,const struct bpf_map_batch_opts *opts) {
    if(forced_batch_error) {errno=forced_batch_error;return -1;}
    int rc=bpf_map_lookup_batch(fd,in,out,keys,values,count,opts);
    int saved=errno;
    if(delete_batch_candidate && *count && (!rc || saved==ENOENT)) {
        bpf_map_delete_elem(fd,keys);delete_batch_candidate=0;
    }
    errno=saved;return rc;
}
#define bpf_map_lookup_batch checked_lookup_batch
#define main observer_program_main
#include "../../observer/common/runtime.c"
#undef main
#undef bpf_map_lookup_batch
#include <sys/socket.h>
#include <sys/wait.h>
const struct backend_ops backend={.name="test",.target=OBJECT_FORK,.scheme=SCHEME_KPROBE};
#define REQUIRE(test) do {if(!(test)) {fprintf(stderr,"runtime_checks:%d: %s\n",__LINE__,#test);return 1;}} while(0)

static struct event sample(unsigned id,unsigned stage) {
    return (struct event){.state={.id=id,.start_ns=1000+id,.stage=stage},
        .lock_addr=(uint64_t)id*4096,.lock_kind=1};
}
static int dedup_check(void) {
    struct observer b={0};
    for(unsigned id=1;id<=20000;id++) {
        struct event e=sample(id,1);
        REQUIRE(live_first(&b,&e));REQUIRE(!live_first(&b,&e));
        e.state.stage=2;
        REQUIRE(live_first(&b,&e));REQUIRE(!live_first(&b,&e));
    }
    REQUIRE(b.live_seen->used==LIVE_SEEN_CAPACITY);
    REQUIRE(b.live_dedup_evictions==20000-LIVE_SEEN_CAPACITY);
    REQUIRE(b.live_lookup_probes<20000*16);
    // Touch the oldest retained record before adding another, verifying true LRU.
    struct event hot=sample(20000-LIVE_SEEN_CAPACITY+1,1);
    REQUIRE(!live_first(&b,&hot));
    struct event next=sample(20001,1);REQUIRE(live_first(&b,&next));
    REQUIRE(!live_first(&b,&hot));
    struct event cold=sample(20000-LIVE_SEEN_CAPACITY+2,1);
    REQUIRE(live_first(&b,&cold));
    printf("DEDUP_PASS probes=%llu bounded_entries=%u\n",
        (unsigned long long)b.live_lookup_probes,b.live_seen->used);
    free(b.live_seen);return 0;
}
static int wait_check(void) {
    int sockets[2];REQUIRE(!socketpair(AF_UNIX,SOCK_STREAM,0,sockets));
    control_fd=sockets[0];struct observer b={0};
    pid_t child=fork();REQUIRE(child>=0);
    if(!child) {usleep(20000);char done='D';_exit(write(sockets[1],&done,1)==1 ? 0 : 1);}
    bool ready=false;uint64_t start=now_ns();
    REQUIRE(!poll_observer(&b,60000,true,&ready));
    REQUIRE(ready && now_ns()-start<1000000000ull);
    REQUIRE(!control_wait('D'));
    int status;REQUIRE(waitpid(child,&status,0)==child && status==0);
    close(sockets[0]);close(sockets[1]);control_fd=-1;
    signal(SIGTERM,stop_handler);stopping=1;start=now_ns();
    REQUIRE(!poll_observer(&b,-1,true,&ready) && now_ns()-start<1000000000ull);
    stopping=0;child=fork();REQUIRE(child>=0);
    if(!child) {usleep(20000);_exit(kill(getppid(),SIGTERM) ? 1 : 0);}
    start=now_ns();REQUIRE(!poll_observer(&b,-1,true,&ready));
    REQUIRE(stopping && now_ns()-start<1000000000ull);
    REQUIRE(waitpid(child,&status,0)==child && status==0);stopping=0;
    puts("WAIT_PASS controller and signal interrupt indefinite sleep");return 0;
}
static void reset_scan(struct observer *b,struct bpf_object *object) {
    free(b->live_seen);
    *b=(struct observer){.object=object,.target=OBJECT_FORK,.timeout=TIMEOUT_POLL,.threshold_ns=1};
}
static int scan_check(const char *path) {
    struct bpf_object *object=bpf_object__open_file(path,NULL);
    REQUIRE(!libbpf_get_error(object));
    struct bpf_program *program;
    bpf_object__for_each_program(program,object)bpf_program__set_autoload(program,false);
    REQUIRE(!bpf_object__load(object));
    int fd=bpf_object__find_map_fd_by_name(object,"states");REQUIRE(fd>=0);
    for(unsigned i=1;i<=700;i++) {
        struct trace_key key={.task=i,.sem=0};
        struct record value={.id=i,.start_ns=now_ns()-1000000000ull,.stage=1,.stack_id=-1};
        REQUIRE(!bpf_map_update_elem(fd,&key,&value,BPF_ANY));
    }
    struct observer b={0};reset_scan(&b,object);
    REQUIRE(!live_scan_map(&b,"states",false));
    REQUIRE(b.live_reports==700 && b.scan_batch_support==1 && !b.scan_scalar_calls);
    REQUIRE(b.scan_batch_calls<20 && map_count(&b,"states")==700);
    REQUIRE(!live_scan_map(&b,"states",false) && b.live_reports==700);
    const int unsupported[]={ENOSYS,EINVAL,EOPNOTSUPP,ENOSPC};
    for(unsigned i=0;i<sizeof(unsupported)/sizeof(unsupported[0]);i++) {
        reset_scan(&b,object);forced_batch_error=unsupported[i];
        REQUIRE(!live_scan_map(&b,"states",false));
        REQUIRE(b.live_reports==700 && b.scan_fallbacks==1 && b.scan_scalar_calls==1);
        forced_batch_error=0;
        REQUIRE(!live_scan_map(&b,"states",false) && b.live_reports==700);
        if(unsupported[i]==ENOSPC)REQUIRE(b.scan_batch_calls>1 && b.scan_scalar_calls==1);
        else REQUIRE(b.scan_batch_calls==1 && b.scan_scalar_calls==2);
    }
    reset_scan(&b,object);delete_batch_candidate=1;
    REQUIRE(!live_scan_map(&b,"states",false));
    REQUIRE(b.live_reports==699 && map_count(&b,"states")==699);
    // A changed record must not be emitted from the old batch contents.
    struct config cfg={0};b.cfg=&cfg;b.collect=COLLECT_STACK;
    int cpus=libbpf_num_possible_cpus();REQUIRE(cpus>0);
    struct counter_values *c=calloc((size_t)cpus,sizeof(*c));REQUIRE(c);
    c[0].value[STACK_ERRORS]=c[0].value[STACK_CAPACITY_ERRORS]=1;
    __u32 zero=0;
    REQUIRE(!bpf_map_update_elem(bpf_object__find_map_fd_by_name(object,"counters"),&zero,c,BPF_ANY));
    stack_health(&b);REQUIRE(b.stack_warning_emitted);stack_health(&b);
    free(c);free(b.live_seen);bpf_object__close(object);
    puts("SCAN_PASS batch, old-kernel fallback, deletion confirmation, stack warning");return 0;
}
static unsigned entry_count(int fd) {
    struct mmap_key key,next;unsigned n=0;int rc=bpf_map_get_next_key(fd,NULL,&next);
    while(!rc && n<9000) {n++;key=next;rc=bpf_map_get_next_key(fd,&key,&next);}return n;
}
static int mmap_check(const char *path) {
    struct bpf_object *object=bpf_object__open_file(path,NULL);REQUIRE(!libbpf_get_error(object));
    struct bpf_program *program;
    bpf_object__for_each_program(program,object)bpf_program__set_autoload(program,false);
    REQUIRE(!bpf_object__load(object));
    int fd=bpf_object__find_map_fd_by_name(object,"mm_records");REQUIRE(fd>=0);
    struct mmap_key key;struct record after;
    struct observer b={.object=object,.target=OBJECT_MMAP,.collect=COLLECT_STATE,.timeout=TIMEOUT_POLL,.threshold_ns=1};
    uint64_t ticks;bool dead;struct record live={.id=((uint64_t)getpid()<<32)|getpid(),.start_ns=now_ns()-1000000000ull,.stage=1,.stack_id=-1};
    REQUIRE(!proc_thread_start(&live,&ticks,&dead) && !dead);
    long hz=sysconf(_SC_CLK_TCK);key=(struct mmap_key){.sem=0x40000,.task=0x1234,.task_start_ns=ticks*1000000000ull/hz};
    REQUIRE(!bpf_map_update_elem(fd,&key,&live,BPF_NOEXIST));
    struct mmap_key stale=key;stale.task_start_ns+=2000000000ull;
    REQUIRE(!bpf_map_update_elem(fd,&stale,&live,BPF_NOEXIST));
    mmap_reap(&b);REQUIRE(entry_count(fd)==1 && b.mmap_reaped==1 && !b.mmap_cleanup_errors);
    REQUIRE(!bpf_map_lookup_elem(fd,&key,&after)); // Same pointer+lock, new lifetime survives.
    stale.sem=0x50000;struct record gone=live;gone.id=0x7ffffffe7ffffffeull;
    REQUIRE(!bpf_map_update_elem(fd,&stale,&gone,BPF_NOEXIST));
    forced_batch_error=ENOSYS;mmap_reap(&b);forced_batch_error=0;
    REQUIRE(entry_count(fd)==1 && b.mmap_reaped==2 && b.scan_scalar_calls);
    REQUIRE(!live_scan_map(&b,"mm_records",true) && b.live_reports==1);
    REQUIRE(b.live_saved[0].event.lock_addr==key.sem && b.live_saved[0].event.lock_kind==1);
    live.stage=3;REQUIRE(!bpf_map_update_elem(fd,&key,&live,BPF_EXIST));
    REQUIRE(!live_scan_map(&b,"mm_records",true) && b.live_reports==2);
    REQUIRE(b.live_saved[1].event.state.stage==3);
    b.collect=COLLECT_COUNT;REQUIRE(!snapshot(&b) && b.owned_count==1 && !b.state_count);
    REQUIRE(!bpf_map_delete_elem(fd,&key));
    free(b.live_seen);bpf_object__close(object);
    puts("MMAP_PASS birth-safe reclamation, count-only snapshot and polling");
    return 0;
}
int main(int argc,char **argv) {
    if(argc<2)return 2;
    if(!strcmp(argv[1],"dedup"))return dedup_check();
    if(!strcmp(argv[1],"wait"))return wait_check();
    if(argc==3 && !strcmp(argv[1],"scan"))return scan_check(argv[2]);
    if(argc==3 && !strcmp(argv[1],"mmap"))return mmap_check(argv[2]);
    return 2;
}
