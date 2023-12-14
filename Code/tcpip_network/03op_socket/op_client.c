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
    //服务器端地址信息结构体
	struct sockaddr_in serv_addr;
    int read_len = 0;

    //BUff
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
        puts("Connected............");
    }

    fputs("Input message(Q to quit):\n", stdout);
    //从命令行接受输入保存到Buff中
    //fgets(message, BUF_SIZE, stdin);

    int nums = 0;
    fputs("Operand nums:",stdout);
    //读取数字
    scanf("%d",&nums);
    message[0] = (char)nums;
    for (int i = 0; i < nums; i++) {
        printf("Operand %d:",i+1);
        //读取输入的数字 并以int的大小放在buff的指定位置
        scanf("%d",(int*)&message[i * 4 + 1]);
    }
    fgetc(stdin);
    fputs("Operand symbol:",stdout);
    scanf("%c",&message[nums * 4 + 1]);
    //发送Buff中的数据
    write(sock,message,nums * 4 + 2);
    int result;
    read(sock,&result, sizeof(int));
    printf("result from server:%d\n",result);


	close(sock);
	return 0;
}

void error_handing(char* message){
	fputs(message,stderr);
	fputs("\n",stderr);
	exit(1);
}
