// SPDX-License-Identifier: GPL-2.0
// Explicit tracefs return-probe capacity; retain native hit/miss diagnostics.
// The BPF programs remain KPROBE programs, with the original entry/return hooks.
#ifndef SUSTAINED_RETPROBE_CAPACITY_H
#define SUSTAINED_RETPROBE_CAPACITY_H
#include <linux/perf_event.h>
#include <sys/syscall.h>

#define RETURN_CAPACITY 512
struct managed_return {
    char name[96]; bool registered;
    unsigned long long hits,missed;
};
static struct managed_return managed_returns[8];
static unsigned managed_return_count;
static const char *managed_tracefs;

static int event_command(const char *command) {
    char path[192];snprintf(path,sizeof(path),"%s/kprobe_events",managed_tracefs);
    int fd=open(path,O_WRONLY|O_APPEND|O_CLOEXEC);if(fd<0)return -1;
    ssize_t n=write(fd,command,strlen(command));int saved=errno;close(fd);
    if(n!=(ssize_t)strlen(command)) {errno=n<0 ? saved : EIO;return -1;}
    return 0;
}
static int remove_managed_returns(void) {
    int error=0;
    for(unsigned i=0;i<managed_return_count;i++) {
        struct managed_return *r=&managed_returns[i];if(!r->registered)continue;
        char command[160];snprintf(command,sizeof(command),"-:kprobes/%.95s\n",r->name);
        if(event_command(command))error=errno;else r->registered=false;
    }
    return error;
}
static struct bpf_link *attach_sized_return(const struct bpf_program *program) {
    const char *section=bpf_program__section_name(program);
    if(strncmp(section,"kretprobe/",10)) {errno=EINVAL;return NULL;}
    if(!managed_tracefs) {
        if(access("/sys/kernel/tracing/kprobe_events",W_OK)==0)managed_tracefs="/sys/kernel/tracing";
        else if(access("/sys/kernel/debug/tracing/kprobe_events",W_OK)==0)managed_tracefs="/sys/kernel/debug/tracing";
        else return NULL;
    }
    if(managed_return_count==8) {errno=E2BIG;return NULL;}
    struct managed_return *r=&managed_returns[managed_return_count++];
    snprintf(r->name,sizeof(r->name),"lock_unified_%d_%s",getpid(),bpf_program__name(program));
    char command[320];snprintf(command,sizeof(command),"r%d:kprobes/%s %s\n",RETURN_CAPACITY,r->name,section+10);
    if(event_command(command))return NULL;
    r->registered=true;
    char path[256];snprintf(path,sizeof(path),"%s/events/kprobes/%s/id",managed_tracefs,r->name);
    FILE *file=fopen(path,"r");if(!file)return NULL;
    unsigned long id;int matched=fscanf(file,"%lu",&id);fclose(file);
    if(matched!=1) {errno=EIO;return NULL;}
    struct perf_event_attr attr={.size=sizeof(attr),.type=PERF_TYPE_TRACEPOINT,.config=id};
    // Same CPU-0 perf-event attachment convention as libbpf's legacy kprobe
    // loader. Kprobe BPF execution is global; do not attach duplicate copies.
    int fd=syscall(__NR_perf_event_open,&attr,-1,0,-1,PERF_FLAG_FD_CLOEXEC);
    if(fd<0)return NULL;
    struct bpf_link *link=bpf_program__attach_perf_event(program,fd);
    if(libbpf_get_error(link)) {int saved=errno;close(fd);errno=saved;}
    return link;
}
static int snapshot_return_profile(void) {
    if(!managed_return_count)return 0;
    char path[192];snprintf(path,sizeof(path),"%s/kprobe_profile",managed_tracefs);
    FILE *file=fopen(path,"r");if(!file)return errno;
    bool found[8]={0};char line[512],event[192];unsigned long long hits,missed;
    while(fgets(line,sizeof(line),file)) {
        if(sscanf(line,"%191s %llu %llu",event,&hits,&missed)!=3)continue;
        char *name=strrchr(event,'/');name=name ? name+1 : event;
        for(unsigned i=0;i<managed_return_count;i++)if(!strcmp(name,managed_returns[i].name)) {
            managed_returns[i].hits=hits;managed_returns[i].missed=missed;found[i]=true;
        }
    }
    fclose(file);
    for(unsigned i=0;i<managed_return_count;i++)if(!found[i])return EIO;
    return 0;
}
static void print_return_profile(unsigned begin,unsigned end) {
    unsigned long long missed=0;
    for(unsigned i=begin;i<end;i++)missed+=managed_returns[i].missed;
    printf("\"retprobe_capacity\":%u,\"retprobe_misses\":%llu,\"retprobe_profile\":[",
        end>begin ? RETURN_CAPACITY : 0,missed);
    for(unsigned i=begin;i<end;i++) {
        struct managed_return *r=&managed_returns[i];
        printf("%s{\"event\":\"%s\",\"hits\":%llu,\"missed\":%llu,\"removed\":%s}",
            i>begin ? "," : "",r->name,r->hits,r->missed,r->registered ? "false" : "true");
    }
    printf("],");
}
#endif
