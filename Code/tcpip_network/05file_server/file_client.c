#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUF_SIZE 1024

void error_handing(char* message);

int main(int argc,char* argv[]){

    //客户端socket描述符
    int sock;

    //文件指针
    FILE* fp;

    //服务器端地址信息结构体
    struct sockaddr_in serv_addr;
    int read_len = 0,write_len = 0,read_cnt = 0;

    //Buff
    char message[BUF_SIZE];

    if (argc != 3) {
        printf("Usage: %s <IP> <port>\n",argv[0]);
        exit(1);
    }

    sock = socket(PF_INET,SOCK_STREAM,0);
    if (sock == -1) {
        error_handing("socket() error!");
    }

    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))==-1) {
        error_handing("connect() error!");
    }else{
        puts("Connected Server...");
    }

    fp = fopen("./receive.dat","wb");

    //接收服务端发送的数据并写入文件
    while((read_cnt = read(sock, message,BUF_SIZE))!=0){
        fwrite(message,1,read_cnt,fp);
    }
    printf("Received file data\n");
    write(sock,"Thank you!",11);

    fclose(fp);
    close(sock);
    return 0;
}

void error_handing(char* message){
    fputs(message,stderr);
    fputs("\n",stderr);
    exit(1);
}
