#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>

/*
 * 测试wait函数
 */


int main(int argc,char* argv[]){

    int status;
    //创建进程
    pid_t pid = fork();

    if(pid == 0){   //child
        fputs("child process\n",stdout);
    } else{
        printf("child process ID: %d\n",pid);
        sleep(15);
        wait(&status);
        if(WIFEXITED(status)){
            printf("Chile send one:%d\n", WEXITSTATUS(status));
        }
        sleep(15);
    }
    if(pid == 0){
        fputs("child Exit!\n",stdout);
        return 99;
    }else{
        fputs("parent Exit!\n",stdout);
    }

}
