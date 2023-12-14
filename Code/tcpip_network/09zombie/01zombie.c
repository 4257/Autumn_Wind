#include <stdio.h>
#include <unistd.h>
/*
 * 测试主进程延迟 子进程是否会销毁
 */


int main(int argc,char* argv[]){
    //创建进程
    pid_t pid = fork();

    if(pid == 0){   //child
        fputs("child process\n",stdout);
    } else{
        printf("child process ID: %d",pid);
        sleep(30);
    }
    if(pid == 0){
        fputs("child Exit!\n",stdout);
    }else{
        fputs("parent Exit!\n",stdout);
    }



}
