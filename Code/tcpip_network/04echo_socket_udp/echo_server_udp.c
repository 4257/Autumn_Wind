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
	serv_sock = socket(PF_INET,SOCK_DGRAM,0);
	if (serv_sock == -1) {
		error_handing("udp socket() error!");
	}

    //为服务器端地址信息结构体初始化地址信息结构体变量
	memset(&serv_addr,0,sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[1]));

    //向服务按套接字分配地址
	if (bind(serv_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) {
		error_handing("udp bind() error!");
	}
    clnt_addr_size = sizeof(clnt_addr);
    while(1){
        read_len = recvfrom(serv_sock,message,BUF_SIZE,0,(struct sockaddr*)&clnt_addr,&clnt_addr_size);
        sendto(serv_sock,message,read_len,0,(struct sockaddr*)&clnt_addr,clnt_addr_size);
    }

	close(serv_sock);
	return 0;
}

void error_handing(char* message){
	fputs(message,stderr);
	fputs("\n",stderr);
	exit(1);
}
