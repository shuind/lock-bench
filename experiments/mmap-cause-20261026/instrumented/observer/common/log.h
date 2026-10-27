// SPDX-License-Identifier: GPL-2.0
#ifndef LOCKBENCH_LOG_H
#define LOCKBENCH_LOG_H
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int log_vline(const char *fmt,va_list args) {
    int saved=errno;char *message=NULL;
    int length=vasprintf(&message,fmt,args);
    if(length<0) {errno=saved;return length;}
    struct timespec now={0};struct tm beijing;char stamp[32]="time-unavailable";
    if(clock_gettime(CLOCK_REALTIME,&now)) {now.tv_sec=time(NULL);now.tv_nsec=0;}
    time_t beijing_seconds=now.tv_sec+8*60*60;
    if(gmtime_r(&beijing_seconds,&beijing))strftime(stamp,sizeof(stamp),"%Y-%m-%d %H:%M:%S",&beijing);
    flockfile(stderr);
    for(const char *line=message;*line;) {
        const char *end=strchr(line,'\n');size_t size=end ? (size_t)(end-line) : strlen(line);
        fprintf(stderr,"%s.%03ld %.*s\n",stamp,now.tv_nsec/1000000,(int)size,line);
        if(!end)break;
        line=end+1;
    }
    funlockfile(stderr);fflush(stderr);free(message);errno=saved;return length;
}
static int log_line(const char *fmt,...) __attribute__((format(printf,1,2)));
static int log_line(const char *fmt,...) {
    va_list args;va_start(args,fmt);int result=log_vline(fmt,args);va_end(args);return result;
}
#endif
