#include <stdio.h>
#include <signal.h>
#include <unistd.h>

//回调函数 信号处理函数 信号处理器
void signal_handler_fun(int signum) {
    printf("catch signal %d\n", signum);
}

void timeout(int sig){
    if(sig == SIGALRM){
        printf("Timeout!\n");
        alarm(2);
    }
}

//回调函数 信号处理函数 信号处理器
void key_control(int sig){
    if(sig == SIGINT){
        fputs("CTRL+C pressed\n",stdout);
    }
}

int main(int argc, char *argv[]) {

    struct sigaction act;
    act.sa_flags = 0;
    act.sa_handler = timeout;
    sigemptyset(&act.sa_mask);

    sigaction(SIGALRM,&act,0);
    alarm(5);
    for (int i = 0; i < 3; ++i) {
        printf("wait...\n");
        sleep(100);
    }
    return 0;
}
