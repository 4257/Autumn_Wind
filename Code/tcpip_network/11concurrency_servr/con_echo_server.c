#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#define BUF_SIZE 1024

void error_handing(char* message);
void dest_process(int sig);

int main(int argc,char* argv[]){
    //初始化信号处理
    pid_t pid;
    int status;
    struct sigaction act;
    act.sa_handler = dest_process;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGCHLD,&act,0);

    //服务器端套接字描述符
	int serv_sock;
    //客户端端套接字描述符
	int clnt_sock;

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
    //受理客户端的连接请求
    while (1) {
        //接受刻客户端的连接请求
        clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr,&clnt_addr_size);
        if (clnt_sock == -1) {
            //error_handing("accept() error!");
            continue;
        }else{
            puts("New Client Connected");
        }
        //创建进程
        pid = fork();
        if(pid == -1){
            close(clnt_sock);
            continue;
        }
        if(pid == 0){   //子进程
            close(serv_sock);//子进程关闭多余的服务端套接字
            while ((read_len = read(clnt_sock,message,BUF_SIZE))!=0){
                write(clnt_sock, message, read_len);
            }
            close(clnt_sock);
            puts("client disconnected...");
            return 0;
        } else{     //父进程
            close(clnt_sock);//父进程关闭多余的客户端套接字
        }
    }
	close(serv_sock);
	return 0;
}

void error_handing(char* message){
	fputs(message,stderr);
	fputs("\n",stderr);
	exit(1);
}
//子进程销毁函数
void dest_process(int sig){
    int status;
    pid_t pid;
    while((pid = waitpid(-1,&status,WNOHANG))>0){
        if(WIFEXITED(status)){
            printf("Removed Child proc: %d \n",pid);
            printf("Child Send: %d \n",WEXITSTATUS(status));
        }
    }
}
