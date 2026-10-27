// Shared work counters present in BOTH baseline and observed executions.
#pragma once
#include <cstdint>
#include <cstdlib>
#include <new>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
struct alignas(128) BenchHeader {
    uint64_t magic=0x56414e4f56455231ULL;
    std::atomic<uint64_t> collecting{0},ready{0};
    uint64_t workers=0,start_ns=0,stop_ns=0,reserved[10]={0};
};
struct alignas(128) BenchRecord {
    std::atomic<uint64_t> visits{0},allocated{0},iterations{0},ready{0};
    uint64_t kind=0,file_bytes=0,initial_nodes=0,reserved[9]={0};
};
static_assert(sizeof(BenchHeader)==128 && sizeof(BenchRecord)==128,"Shared layout");
static_assert(sizeof(std::atomic<uint64_t>)==8,"Atomic layout");
static BenchHeader *benchHeader=nullptr;
static BenchRecord *benchRecords=nullptr;
static int benchPhase=-1;
static std::mutex benchMutex;
static std::condition_variable benchCV;
static bool benchStarted=false;
static thread_local BenchRecord *benchRecord=nullptr;
static thread_local uint64_t benchVisits=0,benchAllocations=0,benchIterations=0;
static uint64_t benchNow(){timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return uint64_t(t.tv_sec)*1000000000ULL+t.tv_nsec;}
static void benchInit(size_t workers){
    const char *name=getenv("BENCH_PROGRESS");if(!name)return;
    const char *phase=getenv("BENCH_PHASE_FD");if(!phase)throw std::runtime_error("BENCH_PHASE_FD missing");
    benchPhase=std::stoi(phase);
    int fd=open(name,O_RDWR|O_CREAT|O_TRUNC,0644);if(fd<0)throw std::runtime_error("Progress open failed");
    size_t size=(workers+1)*128;if(ftruncate(fd,size))throw std::runtime_error("Progress resize failed");
    void *ptr=mmap(nullptr,size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);close(fd);
    if(ptr==MAP_FAILED)throw std::runtime_error("Progress mmap failed");
    benchHeader=new(ptr) BenchHeader;benchHeader->workers=workers;
    benchRecords=reinterpret_cast<BenchRecord*>(static_cast<char*>(ptr)+128);
    for(size_t i=0;i<workers;i++)new(benchRecords+i) BenchRecord;
    if(!benchHeader->collecting.is_lock_free())throw std::runtime_error("64-bit atomics must be lock-free");
}
static void benchReady(size_t slot,uint64_t kind,uint64_t bytes,uint64_t nodes){
    if(!benchHeader)return;
    benchRecord=&benchRecords[slot];benchRecord->kind=kind;benchRecord->file_bytes=bytes;benchRecord->initial_nodes=nodes;
    std::unique_lock<std::mutex> guard(benchMutex);
    benchRecord->ready.store(1,std::memory_order_release);
    uint64_t done=benchHeader->ready.fetch_add(1,std::memory_order_release)+1;
    if(done==benchHeader->workers)benchCV.notify_all();
    benchCV.wait(guard,[]{return benchStarted;});
}
static void benchVisit(uint64_t n){
    if(benchHeader && benchHeader->collecting.load(std::memory_order_relaxed)){
        benchVisits+=n;benchRecord->visits.store(benchVisits,std::memory_order_relaxed);
    }
}
static void benchAllocate(uint64_t n){
    if(benchHeader && benchHeader->collecting.load(std::memory_order_relaxed)){
        benchAllocations+=n;benchRecord->allocated.store(benchAllocations,std::memory_order_relaxed);
    }
}
static void benchIteration(){
    if(benchHeader && benchHeader->collecting.load(std::memory_order_relaxed)){
        benchRecord->iterations.store(++benchIterations,std::memory_order_relaxed);
    }
}
static void benchSession(){
    {std::unique_lock<std::mutex> guard(benchMutex);benchCV.wait(guard,[]{return benchHeader->ready.load(std::memory_order_acquire)==benchHeader->workers;});}
    if(write(benchPhase,"R",1)!=1)throw std::runtime_error("Ready write failed");
    char cmd;if(read(benchPhase,&cmd,1)!=1 || cmd!='G')throw std::runtime_error("Go missing");
    {std::lock_guard<std::mutex> guard(benchMutex);benchHeader->start_ns=benchNow();benchHeader->collecting.store(1,std::memory_order_release);benchStarted=true;}
    benchCV.notify_all();
    // Only the small functional validation requests this known read-lock
    // operation. Formal throughput arms never set BENCH_VALIDATE_READ.
    if(getenv("BENCH_VALIDATE_READ")){
        int fd=open("/proc/self/maps",O_RDONLY);if(fd<0)throw std::runtime_error("Read validation open failed");
        char buffer[4096];ssize_t count;while((count=read(fd,buffer,sizeof(buffer)))>0){}
        close(fd);if(count<0)throw std::runtime_error("Read validation failed");
    }
    if(read(benchPhase,&cmd,1)!=1 || cmd!='D')throw std::runtime_error("Done missing");
    benchHeader->collecting.store(0,std::memory_order_release);benchHeader->stop_ns=benchNow();
    if(write(benchPhase,"S",1)!=1)throw std::runtime_error("Stop acknowledgment failed");
    // Keep the process alive for CPU/map snapshots. The parent terminates it.
    for(;;)pause();
}
