#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 1024

void error_handing(char* message);

int main(int argc,char* argv[]){
    //服务器端套接字描述符
    int serv_sock;
    //客户端端套接字描述符
    int clnt_sock;
    //文件指针
    FILE* fp;

    //Buff
    char message[BUF_SIZE];
    //读取大小
    int read_len;

    //服务器端地址信息结构体
    struct sockaddr_in serv_addr;
    //客户器端地址信息结构体
    struct sockaddr_in clnt_addr;

    //客户端地址信息结构体长度
    socklen_t clnt_addr_size;
    //命令行参数 需要输入端口号
    if (argc != 2) {
        printf("Usage: %s <port>\n",argv[0]);
        exit(1);
    }

    //创建server socket
    serv_sock = socket(PF_INET,SOCK_STREAM,0);
    if (serv_sock == -1) {
        error_handing("socket() error!");
    }

    //为服务器端地址信息结构体初始化地址信息结构体变量
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));

    //向服务按套接字分配地址
    if (bind(serv_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) {
        error_handing("bind() error!");
    }
    //进入等待连接请求状态
    if (listen(serv_sock,5)==-1) {
        error_handing("listen() error!");
    }

    clnt_addr_size = sizeof(clnt_addr);
    //接受刻客户端的连接请求
    clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr,&clnt_addr_size);

    //打开文件：./file_server.c
    fp = fopen("./file_server.c","rb");
    //向客户端发送数据
    while(1){
        //读取文件二进制数据到message 每次1024字节
        read_len = fread(message,1,BUF_SIZE,fp);
        //由于fread会记录上次读取的位置 所以从文件读取的数据直接发送
        //当读取的数据比BUF_SIZE小的时候 发送剩余数据并跳出循环 否则发送所有message的数据
        if(read_len<BUF_SIZE){
            write(clnt_sock,message,read_len);
            break;
        }
        write(clnt_sock,message,BUF_SIZE);
    }

    //半关闭客户端套接字的输出流
    shutdown(clnt_sock,SHUT_WR);

    //接收客户端发送的数据并输出
    read(clnt_sock,message,BUF_SIZE);
    printf("%s\n",message);

    //关闭打开的文件
    fclose(fp);
    //关闭客户端/服务端套接字 发送完就关闭连接
    close(clnt_sock);
    close(serv_sock);

    return 0;
}

void error_handing(char* message){
    fputs(message,stderr);
    fputs("\n",stderr);
    exit(1);
}
