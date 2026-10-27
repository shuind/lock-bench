// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *mode;
static uint64_t operations, duration_ns, start_ns;
static size_t area_bytes;
static unsigned concurrency;
static unsigned char *shared_area;
static pthread_barrier_t barrier;
static atomic_uint prepared;
static atomic_int failed;
struct worker { unsigned index; uint64_t count; int maps, a, b; unsigned char *area; };
static uint64_t now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000000000ull+t.tv_nsec;
}
static int keep(uint64_t count,unsigned index) {
    if (atomic_load(&failed)) return 0;
    if (operations) return count < operations/concurrency+(index<operations%concurrency);
    return now()-start_ns < duration_ns;
}
static int fork_one(void) {
    pid_t p=fork();
    if (!p) _exit(0);
    if (p<0) return errno;
    int status; pid_t result;
    do { result=waitpid(p,&status,0); } while (result<0 && errno==EINTR);
    return result==p && WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : ECHILD;
}
static void *run(void *opaque) {
    struct worker *w=opaque;
    int migration=!strcmp(mode,"cgroup-migrate") || (!strcmp(mode,"fork-migrate") && w->index==concurrency-1);
    if (migration) {
        const char *a=getenv("LOCKBENCH_CGROUP_A"),*b=getenv("LOCKBENCH_CGROUP_B");
        if (!a || !b) atomic_store(&failed,EINVAL);
        else { w->a=open(a,O_WRONLY|O_CLOEXEC); w->b=open(b,O_WRONLY|O_CLOEXEC); }
        if (w->a<0 || w->b<0) atomic_store(&failed,errno);
    }
    if (!strcmp(mode,"read-maps") || (!strcmp(mode,"mmap-contention") && w->index)) {
        w->maps=open("/proc/self/maps",O_RDONLY|O_CLOEXEC);
        if (w->maps<0) atomic_store(&failed,errno);
    }
    if (!strcmp(mode,"fault") || !strcmp(mode,"mprotect")) {
        w->area=mmap(NULL,area_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if (w->area==MAP_FAILED) { w->area=NULL; atomic_store(&failed,errno); }
        else for(size_t i=0;i<area_bytes;i+=4096) w->area[i]=1;
    }
    atomic_fetch_add(&prepared,1); pthread_barrier_wait(&barrier);
    char pid[40],data[16384]; int length=snprintf(pid,sizeof(pid),"%d\n",getpid());
    while (keep(w->count,w->index)) {
        int error=0;
        if (!strcmp(mode,"fork") || (!strcmp(mode,"fork-migrate") && !migration)) error=fork_one();
        else if (migration) {
            if (write(w->count%2?w->b:w->a,pid,length)!=length) error=errno?errno:EIO;
        } else if (!strcmp(mode,"mmap")) {
            void *p=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
            if(p==MAP_FAILED) error=errno;
            else if(munmap(p,4096)) error=errno;
        } else if (!strcmp(mode,"mprotect") || (!strcmp(mode,"mmap-contention") && !w->index)) {
            void *p=shared_area?shared_area:w->area;
            if(mprotect(p,area_bytes,PROT_READ) || mprotect(p,area_bytes,PROT_READ|PROT_WRITE)) error=errno;
        } else if (!strcmp(mode,"fault")) {
            if(madvise(w->area,area_bytes,MADV_DONTNEED)) error=errno;
            else for(size_t i=0;i<area_bytes;i+=4096) ((volatile unsigned char *)w->area)[i]=1;
        } else {
            if(lseek(w->maps,0,SEEK_SET)<0) error=errno;
            else { ssize_t n; do {n=read(w->maps,data,sizeof(data));} while(n>0); if(n<0)error=errno; }
        }
        if(error) {atomic_store(&failed,error);break;}
        w->count++;
    }
    return NULL;
}
int main(int argc,char **argv) {
    if(argc!=6) return 2;
    mode=argv[1]; operations=strtoull(argv[2],NULL,10);
    duration_ns=(uint64_t)(strtod(argv[3],NULL)*1e9); concurrency=strtoul(argv[4],NULL,10);
    area_bytes=(size_t)strtoull(argv[5],NULL,10);
    if(!concurrency || concurrency>1024 || !duration_ns || !area_bytes) return 2;
    if(!strcmp(mode,"mmap-contention")) {
        shared_area=mmap(NULL,area_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(shared_area==MAP_FAILED) return 3;
        if(madvise(shared_area,area_bytes,MADV_NOHUGEPAGE)) return 3;
        for(size_t i=0;i<area_bytes;i+=4096) shared_area[i]=1;
    }
    pthread_t *threads=calloc(concurrency,sizeof(*threads));
    struct worker *workers=calloc(concurrency,sizeof(*workers));
    if(!threads || !workers || pthread_barrier_init(&barrier,NULL,concurrency+1)) return 3;
    for(unsigned i=0;i<concurrency;i++) {
        workers[i]=(struct worker){.index=i,.maps=-1,.a=-1,.b=-1};
        if(pthread_create(&threads[i],NULL,run,&workers[i])) return 3;
    }
    while(atomic_load(&prepared)!=concurrency) sched_yield();
    if(atomic_load(&failed)) return 4;
    puts("{\"phase\":\"ready\"}"); fflush(stdout);
    if(getchar()!='G') return 5;
    start_ns=now(); pthread_barrier_wait(&barrier);
    uint64_t total=0,forks=0,migrations=0;
    for(unsigned i=0;i<concurrency;i++) {
        pthread_join(threads[i],NULL); total+=workers[i].count;
        if(!strcmp(mode,"fork") || (!strcmp(mode,"fork-migrate") && i<concurrency-1)) forks+=workers[i].count;
        if(!strcmp(mode,"cgroup-migrate") || (!strcmp(mode,"fork-migrate") && i==concurrency-1)) migrations+=workers[i].count;
    }
    printf("{\"operations\":%"PRIu64",\"forks\":%"PRIu64",\"migrations\":%"PRIu64",\"error\":%d}\n",total,forks,migrations,atomic_load(&failed));
    fflush(stdout); if(getchar()!='F')return 5;
    for(unsigned i=0;i<concurrency;i++) {
        if(workers[i].area)munmap(workers[i].area,area_bytes);
        if(workers[i].maps>=0)close(workers[i].maps);
        if(workers[i].a>=0)close(workers[i].a);
        if(workers[i].b>=0)close(workers[i].b);
    }
    if(shared_area)munmap(shared_area,area_bytes);
    free(workers);free(threads);pthread_barrier_destroy(&barrier);
    return atomic_load(&failed)?1:0;
}
