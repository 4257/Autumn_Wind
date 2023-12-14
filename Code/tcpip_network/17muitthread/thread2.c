#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void* thread_new(void * arg);

int main(){
    pthread_t t_id;

    int arg = 5;
    void* msg;

    pthread_create(&t_id,NULL, thread_new,&arg);
    pthread_join(t_id,&msg);

    printf("return msg:%s\n",(char*)msg);
    fputs("main stop\n",stdout);
    return 0;
}
void* thread_new(void* arg){
    for (int i = 0; i < *(int*)arg; ++i) {
        sleep(1);
        fputs("thread_new\n",stdout);
    }
    char* msg="abcdefg";
    return (void*)msg;
}
