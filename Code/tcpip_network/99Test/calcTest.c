#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/wait.h>

int main(int argc,char* argv[]){
    char buf[] = "Who are you";
    char buf2[30];
    int fds[2];
    pipe(fds);
    pid_t pid = fork();
    if(pid == 0){
        write(fds[1],buf,sizeof(buf));
    } else{
        read(fds[0],buf2,sizeof(buf2));
        puts(buf2);
    }
    return 0;
}
