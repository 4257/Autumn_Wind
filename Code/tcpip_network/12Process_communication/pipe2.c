#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main(int argc,char* argv[]){
    char buf[] = "Who are you";
    char buf1[] = "Who are you yes";
    char buf2[30];
    int fds[2];
    pipe(fds);
    pid_t pid = fork();
    if(pid == 0){
        write(fds[1],buf,sizeof(buf));
        sleep(2);
        printf("c...\n");
        read(fds[0],buf2,sizeof(buf2));
        printf("C output: %s\n",buf2);
    } else{
        read(fds[0],buf2,sizeof(buf2));
        printf("P output: %s\n",buf2);
        write(fds[1],buf1,sizeof(buf1));
        sleep(3);
    }
    return 0;
}
