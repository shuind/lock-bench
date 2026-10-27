#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static unsigned threads,done,ready;
static uint64_t operations;
static const char *mode;
static size_t page_size;
static unsigned char *region,*buffer;
static unsigned char expected[32];
static pthread_barrier_t barrier,finish;
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond=PTHREAD_COND_INITIALIZER;
static atomic_int failure;
static uint64_t now_ns(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return(uint64_t)t.tv_sec*1000000000ull+t.tv_nsec;}
static void digest(unsigned char out[32],size_t stride) {
    SHA256_CTX context;SHA256_Init(&context);const unsigned char *part=buffer;
    for(unsigned i=0;i<1024;i++,part+=stride)SHA256_Update(&context,part,4096);
    SHA256_Final(out,&context);
}
static void *worker(void *opaque) {
    unsigned index=(unsigned)(uintptr_t)opaque;unsigned char hash[32];
    int hash_mode=!strcmp(mode,"hash") || !strcmp(mode,"hash-small") || !strcmp(mode,"pair-hash");
    size_t stride=!strcmp(mode,"hash-small") ? 0 : 4096;
    if(hash_mode) {digest(hash,stride);if(memcmp(hash,expected,32))atomic_store(&failure,EIO);}
    unsigned char *page=region+(2*index+1)*page_size;
    pthread_mutex_lock(&mutex);ready++;pthread_cond_signal(&cond);pthread_mutex_unlock(&mutex);
    pthread_barrier_wait(&barrier);
    for(uint64_t i=0;i<operations/threads && !atomic_load(&failure);i++) {
        if(mprotect(page,page_size,i&1 ? PROT_READ|PROT_WRITE : PROT_READ)) {atomic_store(&failure,errno);break;}
        if(!strcmp(mode,"sleep")) {struct timespec t={0,200000};while(nanosleep(&t,&t) && errno==EINTR) {}}
        else if(!strcmp(mode,"busy")) {uint64_t stop=now_ns()+200000;while(now_ns()<stop) {}}
        else if(hash_mode && (strcmp(mode,"pair-hash") || (i&1))) {digest(hash,stride);if(memcmp(hash,expected,32))atomic_store(&failure,EIO);}
    }
    pthread_mutex_lock(&mutex);done++;pthread_cond_signal(&cond);pthread_mutex_unlock(&mutex);
    pthread_barrier_wait(&finish);return NULL;
}
int main(int argc,char **argv) {
    if(argc!=4)return 2;
    threads=(unsigned)strtoul(argv[1],NULL,10);operations=strtoull(argv[2],NULL,10);mode=argv[3];
    if(!threads || threads>32 || !operations || operations%threads)return 2;
    if(strcmp(mode,"hot")&&strcmp(mode,"sleep")&&strcmp(mode,"busy")&&strcmp(mode,"hash")&&strcmp(mode,"hash-small")&&strcmp(mode,"pair-hot")&&strcmp(mode,"pair-hash"))return 2;
    page_size=(size_t)sysconf(_SC_PAGESIZE);
    region=mmap(NULL,(2*threads+1)*page_size,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    buffer=malloc(4194304);if(region==MAP_FAILED || !buffer)return 3;
    memset(buffer,0xa5,4194304);digest(expected,4096);
    pthread_t ids[32];
    pthread_barrier_init(&barrier,NULL,threads+1);pthread_barrier_init(&finish,NULL,threads+1);
    for(unsigned i=0;i<threads;i++) {
        if(mprotect(region+(2*i+1)*page_size,page_size,PROT_READ|PROT_WRITE))return 3;
        if(pthread_create(&ids[i],NULL,worker,(void *)(uintptr_t)i))return 3;
    }
    pthread_mutex_lock(&mutex);while(ready<threads)pthread_cond_wait(&cond,&mutex);pthread_mutex_unlock(&mutex);
    puts("{\"phase\":\"ready\"}");fflush(stdout);if(getchar()!='G')return 4;
    struct rusage a,b;getrusage(RUSAGE_SELF,&a);uint64_t start=now_ns();
    pthread_barrier_wait(&barrier);
    pthread_mutex_lock(&mutex);while(done<threads)pthread_cond_wait(&cond,&mutex);pthread_mutex_unlock(&mutex);
    uint64_t wall=now_ns()-start;getrusage(RUSAGE_SELF,&b);
    printf("{\"operations\":%"PRIu64",\"wall_ns\":%"PRIu64",\"threads\":%u,\"error\":%d,\"voluntary_switches\":%ld,\"involuntary_switches\":%ld}\n",
           operations,wall,threads,atomic_load(&failure),b.ru_nvcsw-a.ru_nvcsw,b.ru_nivcsw-a.ru_nivcsw);
    fflush(stdout);if(getchar()!='F')return 4;
    pthread_barrier_wait(&finish);for(unsigned i=0;i<threads;i++)pthread_join(ids[i],NULL);
    munmap(region,(2*threads+1)*page_size);free(buffer);return atomic_load(&failure) ? 1 : 0;
}
