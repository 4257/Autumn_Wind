#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#define BUFF_SIZE 100

void error_handing(char* message);
void writefile();
void readfile();
int main (int argc,char* argv[]){

    readfile();
    return 0;
}

void writefile(){
    int fd;
    char buff[] = "Let go!\n";

    fd = open("test1.txt",O_CREAT|O_WRONLY|O_TRUNC);
    printf("%x\n",fd);

    if(fd == -1){
        error_handing("open() error!");
    }
    if(write(fd,buff,sizeof(buff))==-1){
        error_handing("write() error!");
    }
    close(fd);
    return;
}
void readfile(){
    int fd;
    char buff[BUFF_SIZE];

    fd = open("test1.txt",O_RDONLY);
    printf("%x\n",fd);

    if(fd == -1){
        error_handing("open() error!");
    }
    if(read(fd,buff,sizeof(buff))==-1){
        error_handing("write() error!");
    }
    printf("file date: %s\n",buff);
    close(fd);
    return;
}

void error_handing(char* message){
    fputs(message,stderr);
    fputs("\n",stderr);
    exit(1);
}
