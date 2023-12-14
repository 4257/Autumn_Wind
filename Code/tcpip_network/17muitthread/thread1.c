#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void* thread_new(void * arg);

int main(){
    pthread_t t_id;
    int arg = 5;
    pthread_create(&t_id,NULL, thread_new,&arg);
    sleep(10);
    fputs("main stop\n",stdout);
    return 0;
}
void* thread_new(void* arg){
    for (int i = 0; i < *(int*)arg; ++i) {
        sleep(1);
        fputs("thread_new\n",stdout);
    }
}
