// SPDX-License-Identifier: GPL-2.0
// Read active states and saved stacks; reclaim only confirmed exited mmap keys.
#define LIVE_SEEN_CAPACITY 8192
#define LIVE_BUCKETS 16384
struct live_seen {
    uint64_t id,start_ns,sem;
    unsigned kind,stages,hash_next,hash_prev,prev,next;
};
struct live_cache {
    struct live_seen entries[LIVE_SEEN_CAPACITY+1];
    unsigned buckets[LIVE_BUCKETS],used,oldest,newest;
};
struct live_symbol { uint64_t addr;char *name; };
static struct live_symbol *live_symbols;
static size_t live_symbol_count;
static bool live_symbols_loaded;
static int live_symbol_compare(const void *a,const void *b) {
    uint64_t x=((const struct live_symbol *)a)->addr,y=((const struct live_symbol *)b)->addr;
    return (x>y)-(x<y);
}
static void live_symbols_load(void) {
    if(live_symbols_loaded)return;live_symbols_loaded=true;
    FILE *f=fopen("/proc/kallsyms","r");if(!f)return;
    char line[1024],name[256],type;unsigned long long addr;size_t capacity=0;
    while(fgets(line,sizeof(line),f)) {
        if(sscanf(line,"%llx %c %255s",&addr,&type,name)!=3 || !addr || !strchr("tTwW",type))continue;
        if(live_symbol_count==capacity) {
            size_t n=capacity ? capacity*2 : 4096;
            void *p=realloc(live_symbols,n*sizeof(*live_symbols));if(!p)break;
            live_symbols=p;capacity=n;
        }
        char *copy=strdup(name);if(!copy)break;
        live_symbols[live_symbol_count++]=(struct live_symbol){addr,copy};
    }
    fclose(f);
    if(live_symbol_count)qsort(live_symbols,live_symbol_count,sizeof(*live_symbols),live_symbol_compare);
}
static void live_symbols_free(void) {
    for(size_t i=0;i<live_symbol_count;i++)free(live_symbols[i].name);
    free(live_symbols);live_symbols=NULL;live_symbol_count=0;
}
static void live_print_stack(struct observer *b,int id) {
    if(id<0) {log_line("  entry_stack: not collected");return;}
    __u32 key=id>=4096 ? id-4096 : id;__u64 ips[32]={0};
    int fd=map_fd(b,id>=4096 ? "stack_overflow" : "stacks");
    if(fd<0 || bpf_map_lookup_elem(fd,&key,ips)) {
        log_line("  entry_stack: unavailable (id=%d)",id);return;
    }
    live_symbols_load();log_line("  entry_stack:");
    for(unsigned i=0;i<32 && ips[i];i++) {
        size_t lo=0,hi=live_symbol_count;
        while(lo<hi) {size_t mid=lo+(hi-lo)/2;if(live_symbols[mid].addr<=ips[i])lo=mid+1;else hi=mid;}
        // Dynamic BPF trampolines may not be present in kallsyms; keep raw IPs.
        if(lo && ips[i]-live_symbols[lo-1].addr<1024*1024)
            log_line("    #%u 0x%llx %s+0x%llx",i,(unsigned long long)ips[i],live_symbols[lo-1].name,(unsigned long long)(ips[i]-live_symbols[lo-1].addr));
        else log_line("    #%u 0x%llx",i,(unsigned long long)ips[i]);
    }
}
static unsigned live_bucket(uint64_t id,uint64_t start,uint64_t sem,unsigned kind) {
    uint64_t hash=id^(start*11400714819323198485ull)^sem^kind;
    hash^=hash>>30;hash*=0xbf58476d1ce4e5b9ull;
    hash^=hash>>27;hash*=0x94d049bb133111ebull;hash^=hash>>31;
    return hash&(LIVE_BUCKETS-1);
}
static void live_unlink_age(struct live_cache *cache,unsigned at) {
    struct live_seen *s=&cache->entries[at];
    if(s->prev)cache->entries[s->prev].next=s->next;else cache->oldest=s->next;
    if(s->next)cache->entries[s->next].prev=s->prev;else cache->newest=s->prev;
}
static void live_touch(struct live_cache *cache,unsigned at) {
    struct live_seen *s=&cache->entries[at];s->prev=cache->newest;s->next=0;
    if(cache->newest)cache->entries[cache->newest].next=at;else cache->oldest=at;
    cache->newest=at;
}
static bool live_first(struct observer *b,const struct event *e) {
    if(!b->live_seen)b->live_seen=calloc(1,sizeof(*b->live_seen));
    if(!b->live_seen) {
        if(!b->live_poll_errors++)log_line("Cannot allocate live alert deduplication table");
        return false;
    }
    const struct record *r=&e->state;
    struct live_cache *cache=b->live_seen;
    unsigned bucket=live_bucket(r->id,r->start_ns,e->lock_addr,e->lock_kind);
    for(unsigned at=cache->buckets[bucket];at;at=cache->entries[at].hash_next) {
        struct live_seen *s=&cache->entries[at];b->live_lookup_probes++;
        if(s->id==r->id && s->start_ns==r->start_ns && s->sem==e->lock_addr && s->kind==e->lock_kind) {
            unsigned bit=1u<<r->stage;live_unlink_age(cache,at);live_touch(cache,at);
            if(s->stages&bit)return false;s->stages|=bit;return true;
        }
    }
    unsigned at;
    if(cache->used<LIVE_SEEN_CAPACITY)at=++cache->used;
    else {
        at=cache->oldest;struct live_seen *old=&cache->entries[at];
        unsigned old_bucket=live_bucket(old->id,old->start_ns,old->sem,old->kind);
        if(old->hash_prev)cache->entries[old->hash_prev].hash_next=old->hash_next;
        else cache->buckets[old_bucket]=old->hash_next;
        if(old->hash_next)cache->entries[old->hash_next].hash_prev=old->hash_prev;
        live_unlink_age(cache,at);b->live_dedup_evictions++;
    }
    struct live_seen *slot=&cache->entries[at];
    *slot=(struct live_seen){.id=r->id,.start_ns=r->start_ns,.sem=e->lock_addr,
        .kind=e->lock_kind,.stages=1u<<r->stage,.hash_next=cache->buckets[bucket]};
    if(slot->hash_next)cache->entries[slot->hash_next].hash_prev=at;
    cache->buckets[bucket]=at;live_touch(cache,at);return true;
}
static void live_event(struct observer *b,const struct event *e,const char *source) {
    const struct record *r=&e->state;
    if(!r->start_ns || (r->stage!=1 && r->stage!=2 && !(b->target==OBJECT_MMAP && r->stage==3)) || e->now_ns<r->start_ns ||
        e->now_ns-r->start_ns<b->threshold_ns)return;
    if(!live_first(b,e))return;
    const char *stage=b->target==OBJECT_MMAP && r->stage==3 ? "conflict" : b->target==OBJECT_FORK ? "fork-section" :
        b->scheme==SCHEME_CONTENTION ? "waiting" : r->stage==1 ? "waiting" : "held";
    const char *kind=b->target==OBJECT_MMAP ? (e->lock_kind==2 ? "write" : "read") :
        b->target==OBJECT_FORK ? "none" : b->scheme==SCHEME_CONTENTION ? "unknown" : "write";
    uint64_t since=r->stage==2 && r->acquired_ns ? r->acquired_ns : r->start_ns;
    double stage_ms=e->now_ns>=since ? (e->now_ns-since)/1e6 : 0;
    log_line("SLOW source=%s target=%s pid=%u tid=%u lock=0x%llx kind=%s stage=%s elapsed_ms=%.3f stage_ms=%.3f stack_id=%d",
        source,objects[b->target],(__u32)(r->id>>32),(__u32)r->id,(unsigned long long)e->lock_addr,
        kind,stage,(e->now_ns-r->start_ns)/1e6,stage_ms,r->stack_id);
    live_print_stack(b,r->stack_id);fflush(stderr);b->live_reports++;
    if(b->live_saved_count<256)b->live_saved[b->live_saved_count++]=(struct live_saved){*e,!strcmp(source,"timer")};
}
static void live_candidate(struct observer *b,int fd,const unsigned char *key,
        const unsigned char *value,bool mmap_state) {
    struct record r;memcpy(&r,value,sizeof(r));uint64_t now=now_ns();
    unsigned char confirm[64]={0};
    // Both batch and scalar traversal are sampled views; confirm slow candidates.
    if(r.start_ns && now>=r.start_ns && now-r.start_ns>=b->threshold_ns &&
        (r.stage==1 || r.stage==2 || (mmap_state && r.stage==3)) && !(r.stage==1 && r.acquired_ns) &&
        (r.stage!=2 || (r.acquired_ns>=r.start_ns && r.acquired_ns<=now)) &&
        !bpf_map_lookup_elem(fd,key,confirm) && !memcmp(value,confirm,sizeof(r))) {
        if(mmap_state && mmap_cleanup_candidate(b,fd,key,value))return;
        struct event e={.state=r,.now_ns=now};memcpy(&e.lock_addr,key+(mmap_state ? 0 : 8),sizeof(e.lock_addr));
        if(mmap_state) {struct mmap_key k;memcpy(&k,key,sizeof(k));e.lock_kind=k.write ? 2 : 1;}
        live_event(b,&e,"poll");
    }
}
typedef void (*record_visitor)(struct observer *,int,const unsigned char *,const unsigned char *,bool);
static int live_scan_scalar(struct observer *b,int fd,struct bpf_map *map,bool mmap_state,record_visitor visit) {
    unsigned char key[64]={0},next[64]={0},value[64]={0};
    size_t key_size=bpf_map__key_size(map);b->scan_scalar_calls++;
    int rc=bpf_map_get_next_key(fd,NULL,next);
    unsigned budget=bpf_map__max_entries(map)*2+1;
    while(!rc && budget--) {
        if(!bpf_map_lookup_elem(fd,next,value))visit(b,fd,next,value,mmap_state);
        else if(errno!=ENOENT)return errno;
        memcpy(key,next,key_size);rc=bpf_map_get_next_key(fd,key,next);
    }
    if(rc && errno!=ENOENT)return errno;
    return 0;
}
static int visit_map(struct observer *b,const char *name,bool mmap_state,record_visitor visit) {
    int fd=map_fd(b,name);if(fd<0)return 0;
    struct bpf_map *map=bpf_object__find_map_by_name(b->object,name);
    size_t key_size=bpf_map__key_size(map),value_size=bpf_map__value_size(map);
    if(key_size>64 || key_size<(mmap_state ? sizeof(struct mmap_key) : 16u) || value_size>64 || value_size<sizeof(struct record))return EPROTO;
    if(b->scan_batch_support<0)return live_scan_scalar(b,fd,map,mmap_state,visit);
    unsigned char keys[64*64],values[64*64],cursor[64]={0},next[64]={0};
    bool first=true;unsigned budget=bpf_map__max_entries(map)*2+1;
    while(budget) {
        __u32 count=budget<64 ? budget : 64;b->scan_batch_calls++;
        int rc=bpf_map_lookup_batch(fd,first ? NULL : cursor,next,keys,values,&count,NULL);
        int error=rc ? errno : 0;
        if(error && error!=ENOENT) {
            // Older/vendor kernels may not implement batch for this map type.
            if(error==EINVAL || error==ENOSYS || error==EOPNOTSUPP || error==ENOSPC) {
                if(error!=ENOSPC)b->scan_batch_support=-1;
                b->scan_fallbacks++;return live_scan_scalar(b,fd,map,mmap_state,visit);
            }
            return error;
        }
        b->scan_batch_support=1;
        if(count>64 || count>budget)return EPROTO;
        for(unsigned i=0;i<count;i++)visit(b,fd,keys+i*key_size,values+i*value_size,mmap_state);
        budget-=count;
        if(error==ENOENT || !count)break;
        memcpy(cursor,next,sizeof(cursor));first=false;
    }
    return 0;
}
static int live_scan_map(struct observer *b,const char *name,bool mmap_state) {
    return visit_map(b,name,mmap_state,live_candidate);
}
static void reap_candidate(struct observer *b,int fd,const unsigned char *key,const unsigned char *value,bool mmap_state) {
    mmap_cleanup_candidate(b,fd,key,value);
}
static void mmap_reap(struct observer *b) {
    if(!b->object || b->target!=OBJECT_MMAP)return;
    int e=visit_map(b,"mm_records",true,reap_candidate);if(e)mmap_cleanup_error(b,e);
}
static void live_scan(struct observer *b) {
    if(!b->object || b->timeout!=TIMEOUT_POLL)return;
    int e=live_scan_map(b,b->target==OBJECT_MMAP ? "mm_records" : "states",b->target==OBJECT_MMAP);
    if(e && !b->live_poll_errors++)log_line("State polling failed for %s: %s",objects[b->target],strerror(e));
}
