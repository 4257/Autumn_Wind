#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#define NUM_THREAD 100

void* thread_inc(void * arg);
void* thread_des(void * arg);

long long num;
pthread_mutex_t mutex;

int main(){
    pthread_t t_id[NUM_THREAD];

    pthread_mutex_init(&mutex,NULL);

    printf("sizeof longlong %ld\n",sizeof num);

    for (int i = 0; i < NUM_THREAD; ++i) {
        if(i%2)
            pthread_create(&(t_id[i]),NULL, thread_inc,NULL);
        else
            pthread_create(&(t_id[i]),NULL, thread_des,NULL);
    }
    for (int i = 0; i < NUM_THREAD; ++i) {
        pthread_join(t_id[i],NULL);
    }

    printf("return msg:%lld\n",num);
    fputs("main stop\n",stdout);

    pthread_mutex_destroy(&mutex);

    return 0;
}
void* thread_inc(void * arg){
    int i;
    pthread_mutex_lock(&mutex);
    while(i<50000000){
        num+=1;
        i++;

    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

void* thread_des(void * arg){
    int i;

    while(i<50000000){
        pthread_mutex_lock(&mutex);
        num-=1;
        pthread_mutex_unlock(&mutex);
        i++;
    }
    return NULL;
}
