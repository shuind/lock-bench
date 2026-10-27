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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { PAGE_BYTES=4096 };
static unsigned THREADS=4;
static size_t ANON_BYTES=16*1024*1024;
static const volatile unsigned char *region;
static size_t pages,passes;
static pthread_barrier_t barrier;
static atomic_uint ready_count;
struct worker {unsigned index;pid_t tid;uint64_t sum;};
static void fail(const char *what) {perror(what);exit(1);}
static uint64_t scan(unsigned index,size_t repetitions) {
    uint64_t sum=0;size_t first=pages*index/THREADS,last=pages*(index+1)/THREADS;
    for(size_t repeat=0;repeat<repetitions;repeat++)
        for(size_t page=first;page<last;page++)
            sum+=*(const volatile uint64_t *)(region+page*PAGE_BYTES);
    return sum;
}
static void *worker_main(void *opaque) {
    struct worker *w=opaque;w->tid=(pid_t)syscall(SYS_gettid);
    atomic_fetch_add(&ready_count,1);pthread_barrier_wait(&barrier);
    w->sum=scan(w->index,passes);return NULL;
}
int main(int argc,char **argv) {
    if(argc!=5 || sysconf(_SC_PAGESIZE)!=PAGE_BYTES)return 2;
    ANON_BYTES=strtoull(argv[3],NULL,10)*1024*1024;THREADS=strtoul(argv[4],NULL,10);
    if(!ANON_BYTES || !THREADS || THREADS>1024)return 2;
    char *end;passes=strtoull(argv[2],&end,10);if(*end || !passes || passes>100000)return 2;
    int fd=open(argv[1],O_RDONLY|O_CLOEXEC);if(fd<0)fail("open input");
    struct stat st;if(fstat(fd,&st) || st.st_size<=0 || st.st_size%PAGE_BYTES)fail("input size");
    pages=(size_t)st.st_size/PAGE_BYTES;
    unsigned char *ballast=mmap(NULL,ANON_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(ballast==MAP_FAILED)fail("anonymous mmap");memset(ballast,0xa5,ANON_BYTES);
    region=mmap(NULL,st.st_size,PROT_READ,MAP_SHARED,fd,0);if(region==MAP_FAILED)fail("file mmap");
    // One whole-dataset warmup under the same cap. No mmap, munmap, madvise,
    // explicit reclaim or cache-dropping call occurs inside the measured scan.
    uint64_t warmed=0;for(unsigned i=0;i<THREADS;i++)warmed+=scan(i,1);
    uint64_t expected=(uint64_t)pages*(pages-1)/2;if(warmed!=expected)return 4;
    pthread_t threads[THREADS];struct worker workers[THREADS];memset(workers,0,sizeof(workers));
    if(pthread_barrier_init(&barrier,NULL,THREADS+1))return 5;
    for(unsigned i=0;i<THREADS;i++) {workers[i].index=i;if(pthread_create(&threads[i],NULL,worker_main,&workers[i]))return 5;}
    while(atomic_load(&ready_count)!=THREADS)sched_yield();
    printf("{\"pid\":%d,\"threads\":%u,\"worker_tids\":[",getpid(),THREADS);
    for(unsigned i=0;i<THREADS;i++)printf("%s%d",i ? "," : "",workers[i].tid);
    printf("],\"file_bytes\":%lld,\"anon_bytes\":%zu,\"pages\":%zu,\"warmup_verified\":true}\n",(long long)st.st_size,ANON_BYTES,pages);fflush(stdout);
    if(getchar()!='G')return 6;pthread_barrier_wait(&barrier);
    uint64_t actual=0;
    for(unsigned i=0;i<THREADS;i++) {if(pthread_join(threads[i],NULL))return 5;actual+=workers[i].sum;}
    if(actual!=expected*passes)return 7;
    printf("{\"passes\":%zu,\"page_visits\":%zu,\"checksum\":%" PRIu64 ",\"expected_checksum\":%" PRIu64 ",\"verified\":true}\n",passes,pages*passes,actual,expected*passes);fflush(stdout);
    if(getchar()!='F')return 6;
    pthread_barrier_destroy(&barrier);munmap((void *)region,st.st_size);munmap(ballast,ANON_BYTES);close(fd);return 0;
}
