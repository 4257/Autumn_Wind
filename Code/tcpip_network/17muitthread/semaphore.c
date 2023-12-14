#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

void* read1(void *arg);
void* accu(void *arg);

static sem_t sem_one;
static sem_t sem_two;
static int num;

int main(int argc,char * argv[]){
    pthread_t t_id0,t_id1;

    sem_init(&sem_one,0,0);
    sem_init(&sem_two,0,1);

    printf("sem_one value:%ld\n",sem_one.__align);
    printf("sem_two value:%ld\n",sem_two.__align);


    pthread_create(&t_id0,NULL,read1,NULL);
    pthread_create(&t_id1,NULL,accu,NULL);

//    pthread_detach(t_id0);
//    pthread_detach(t_id1);

    pthread_join(t_id0,NULL);
    pthread_join(t_id1,NULL);

    printf("sem_one value:%ld\n",sem_one.__align);
    printf("sem_two value:%ld\n",sem_two.__align);

    sem_destroy(&sem_one);
    sem_destroy(&sem_two);
    return 0;
}

void* read1(void *arg){
    int i;
    for (i = 0; i < 5; ++i) {
        fputs("input num: ",stdout);
        sem_wait(&sem_two);
        scanf("%d",&num);
        sem_post(&sem_one);
    }
    return NULL;
}
void* accu(void *arg){
    int sum,i;
    for (i = 0; i < 5; ++i) {
        sem_wait(&sem_one);
        sum+=num;
        printf("sum: %d\n",sum);
        sem_post(&sem_two);
    }
    printf("sum: %d\n",sum);
    return NULL;
}
