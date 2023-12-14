#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 1024

void error_handing(char* message);

int clac_op(int opnum,int opnds[] ,char oprator);

int main(int argc,char* argv[]){
    //服务器端套接字描述符
    int serv_sock;
    //客户端端套接字描述符
    int clnt_sock;

    //Buff
    char message[BUF_SIZE];
    //读取大小
    int result,opnd_cnt,recv_cnt,recv_len;

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
    //受理5个客户端的连接请求
    for (int i = 0; i < 5; i++) {
        opnd_cnt = 0;
        //接受刻客户端的连接请求
        clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr,&clnt_addr_size);
        read(clnt_sock,&opnd_cnt,1);

        recv_len = 0;
        while((opnd_cnt*4+1) > recv_len){
            recv_cnt = read(clnt_sock,&message[recv_len],BUF_SIZE-1);
            recv_len += recv_cnt;
        }

        result = clac_op(opnd_cnt,(int*)message, message[recv_len-1]);
        write(clnt_sock,(char*)&result,4);
        close(clnt_sock);
    }

    close(serv_sock);
    return 0;
}

void error_handing(char* message){
    fputs(message,stderr);
    fputs("\n",stderr);
    exit(1);
}

int clac_op(int nums,int opnds[],char symbol){
    int result = opnds[0],i;
    switch (symbol) {
        case '+':
            for (i = 1; i < nums; i++) {
                result += opnds[i];
            }
            break;
        case '*':
            for (i = 1; i < nums; i++) {
                result *= opnds[i];
            }
            break;
        case '-':
            for (i = 1; i < nums; i++) {
                result -= opnds[i];
            }
            break;
    }
    return result;
}
