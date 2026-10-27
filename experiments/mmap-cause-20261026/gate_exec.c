#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
int main(int argc,char **argv) {
    const char *env=getenv("DIAGNOSTIC_GATE_FD");
    if(argc<2 || !env)return 2;
    int fd=atoi(env);char ch;
    if(write(fd,"R",1)!=1 || read(fd,&ch,1)!=1 || ch!='G')return 3;
    close(fd);unsetenv("DIAGNOSTIC_GATE_FD");
    execvp(argv[1],argv+1);perror("execvp");return 4;
}
