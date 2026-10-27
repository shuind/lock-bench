// User-space exit reclamation for the unified mmap map. No per-task slot index
// and no newer BPF iteration helper are required. Use the host /proc view.
static int proc_thread_start(const struct record *r,uint64_t *ticks,bool *exited) {
    // Direct TID lookup also works after the thread-group leader has exited.
    char path[64];snprintf(path,sizeof(path),"/proc/%u/stat",(__u32)r->id);
    FILE *f=fopen(path,"r");if(!f)return errno==ENOENT || errno==ESRCH ? 1 : -errno;
    char line[4096];size_t n=fread(line,1,sizeof(line)-1,f);
    int error=ferror(f) ? EIO : 0;fclose(f);if(error)return -error;line[n]=0;
    char *p=strrchr(line,')');if(!p || p[1]!=' ')return -EPROTO;
    p+=2;*exited=*p=='Z' || *p=='X' || *p=='x';
    for(unsigned field=3;field<22;field++) {p=strchr(p,' ');if(!p)return -EPROTO;p++;}
    char *end;errno=0;*ticks=strtoull(p,&end,10);return errno || end==p ? -EPROTO : 0;
}
static int proc_clock(struct observer *b) {
    if(b->proc_clock_ready)return 0;
    FILE *f=fopen("/proc/self/timens_offsets","r");
    if(!f) {if(errno!=ENOENT)return -errno;b->proc_clock_ready=true;return 0;}
    char name[32];long long sec,nsec;
    while(fscanf(f,"%31s %lld %lld",name,&sec,&nsec)==3)if(!strcmp(name,"boottime")) {
        if(sec>INT64_MAX/1000000000ll || sec<INT64_MIN/1000000000ll) {fclose(f);return -ERANGE;}
        b->boot_offset_ns=sec*1000000000ll+nsec;
    }
    int error=ferror(f) ? -EIO : 0;fclose(f);if(!error)b->proc_clock_ready=true;return error;
}
static int mmap_thread_dead(struct observer *b,const struct mmap_key *key,const struct record *r) {
    uint64_t ticks;bool exited=false;int status=proc_thread_start(r,&ticks,&exited);
    if(status)return status;if(exited)return 1;
    status=proc_clock(b);if(status)return status;
    long hz=sysconf(_SC_CLK_TCK);if(hz<=0 || hz>1000000000)return -EINVAL;
    uint64_t ns=key->task_start_ns;
    if(b->boot_offset_ns>=0) {if(UINT64_MAX-ns<(uint64_t)b->boot_offset_ns)return -ERANGE;ns+=(uint64_t)b->boot_offset_ns;}
    else {uint64_t sub=-(uint64_t)b->boot_offset_ns;ns=ns<sub ? 0 : ns-sub;}
    uint64_t expected=ns/1000000000ull*(uint64_t)hz+(ns%1000000000ull)*(uint64_t)hz/1000000000ull;
    return ticks!=expected;
}
static void mmap_cleanup_error(struct observer *b,int error) {
    if(!b->mmap_cleanup_errors++)log_line("Mmap record cleanup failed: %s",strerror(error<0 ? -error : error));
}
static bool mmap_cleanup_candidate(struct observer *b,int fd,const unsigned char *raw_key,
        const unsigned char *raw_value) {
    struct mmap_key key;struct record value,confirm;
    memcpy(&key,raw_key,sizeof(key));memcpy(&value,raw_value,sizeof(value));
    int dead=mmap_thread_dead(b,&key,&value);
    if(dead<0) {mmap_cleanup_error(b,dead);return false;}
    if(!dead)return false;
    if(bpf_map_lookup_elem(fd,&key,&confirm))return true;
    if(memcmp(&confirm,&value,sizeof(value)))return true;
    int timers=map_fd(b,"mm_timers");
    // Deleting a timer-map element cancels its timer through the kernel's map cleanup.
    if(timers>=0 && bpf_map_delete_elem(timers,&key) && errno!=ENOENT) {mmap_cleanup_error(b,errno);return true;}
    if(!bpf_map_delete_elem(fd,&key)) {b->mmap_reaped++;if(value.stage!=3)b->mmap_reaped_aborted++;}
    else if(errno!=ENOENT)mmap_cleanup_error(b,errno);
    return true;
}
