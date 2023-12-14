#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

//子进程销毁函数
void dest_process(int sig){
    int status;
    pid_t pid;
    while((pid = waitpid(-1,&status,WNOHANG))>0){
        if(WIFEXITED(status)){
            printf("Removed Child proc: %d \n",pid);
            printf("Child Send: %d \n",WEXITSTATUS(status));
        }
    }
}

int main(int argc,char* argv[]){

    pid_t pid;
    int status;
    //初始化结构体
    struct sigaction act;
    act.sa_handler = dest_process;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    //注册信号
    sigaction(SIGCHLD,&act,0);
    //创建进程
    pid = fork();
    if(pid == 0) { //子进程
        puts("First Child process!\n");
        sleep(10);
        return 44;
    }else{
        printf("First Child PID:%d\n",pid);
        pid = fork();
        if(pid == 0){
            puts("Second Child process!\n");
            sleep(10);
            exit(66);
        }else{
            printf("Second Child PID:%d\n",pid);
            for (int i = 0; i < 5; i++) {
                puts("wait...\n");
                sleep(5);
            }
        }
    }
    return 0;
}
