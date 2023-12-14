#include <stdio.h>
#include <pthread.h>
#include <unistd.h>


void* thread_sum(void * arg);
int sum;

int main(){
    pthread_t t_id1,t_id2;

    int range1[] = {1,5};
    int range2[] = {6,10};

    pthread_create(&t_id1,NULL, thread_sum,&range1);
    pthread_create(&t_id2,NULL, thread_sum,&range2);
    pthread_join(t_id1,NULL);
    pthread_join(t_id2,NULL);

    printf("return msg:%d\n",sum);
    fputs("main stop\n",stdout);
    return 0;
}
void* thread_sum(void* arg){
    int start = ((int*)arg)[0];
    int end = ((int*)arg)[1];
    for (int i = start; i <= end; i++) {
        sum += i;
    }
    return NULL;
}
