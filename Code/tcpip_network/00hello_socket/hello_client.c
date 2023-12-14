#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>


void error_handing(char* message);

int main(int argc,char* argv[]){
	int sock;
	
	struct sockaddr_in serv_addr;
	int str_len;

	char message[30];

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
		error_handing("bind() error!");
	}

	str_len = read(sock, message,sizeof(message)-1);
    printf("Str_Len:%d\n",str_len);
	if (str_len == -1) {
		error_handing("read() error!");
	}

	printf("Message from server : %s \n",message);

	close(sock);
	return 0;
}

void error_handing(char* message){
	fputs(message,stderr);
	fputs("\n",stderr);
	exit(1);
}
