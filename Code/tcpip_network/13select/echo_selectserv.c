#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 1024

void error_handing(char* message);
void prtfd(char* str,fd_set fd);

int main(int argc,char* argv[]){
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
    printf("serv_sock = %d\n",serv_sock);
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

    fd_set reads,copy_reads;
    prtfd("reads_create",reads);
    struct timeval timeout;
    int fd_max,str_len,fd_num;

    FD_ZERO(&reads);
    prtfd("reads_ZERO",reads);
    //向要传递到select函数第二个参数的fd_set变量reads注册服务端套接字 接收数据的监视对象就包含了服务端套接字
    //客户端的连接请求同样通过传输数据完成 因此 服务端中有接收的数据 就意味着有新的连接请求
    FD_SET(serv_sock,&reads);
    prtfd("reads_set_serv_sock",reads);
    fd_max = serv_sock;

	clnt_addr_size = sizeof(clnt_addr);
    while(1){

        copy_reads = reads;
        prtfd("copy_reads",copy_reads);
        timeout.tv_sec = 5;
        timeout.tv_usec = 5000;
        //监视是否有待读取的数据
        if((fd_num = select(fd_max + 1,&copy_reads,0,0,&timeout)) == -1){
            break;
        }
        if(fd_num ==0){
            continue;
        }
        printf("fd_num : %x\n",fd_num);
        //select函数返回大于1的情况时执行
        for (int i = 0; i < fd_max + 1; ++i) {
            //查找发生状态变化的文件描述符（有接收数据的套接字）
            if(FD_ISSET(i,&copy_reads)){
                prtfd("copy_reads_FD_ISSET",copy_reads);
                //发生变化时 首先验证服务端套接字是否发生变化 如果是服务端套接字的变化
                //将受理连接请求
                if(i == serv_sock){
                    printf("serv_sock_i = %d\n",i);
                    clnt_sock = accept(serv_sock,(struct sockaddr*)&clnt_addr,&clnt_addr_size);
                    printf("clnt_sock :%d \n",clnt_sock);
                    //注册了客户端连接的套接字文件描述符
                    FD_SET(clnt_sock,&reads);
                    prtfd("reads_set_client",reads);
                    prtfd("copy_reads_set_client",copy_reads);
                    if(fd_max < clnt_sock){
                        fd_max = clnt_sock;
                    }
                    printf("Connected client :%d\n",clnt_sock);
                //发生变化的套接字并非服务端套接字时 即有要接受的数据
                }else{
                    printf("server else = %d\n",i);
                    str_len = read(i,message,BUF_SIZE);
                    if(str_len == 0){
                        FD_CLR(i,&reads);
                        prtfd("reads_CLR",reads);
                        close(i);
                        printf("closed client :%d \n",i);
                    } else{
                        write(i,message,str_len);
                    }
                }
           }
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
void prtfd(char* str,fd_set fd){
    char* temp = (char*)&fd;
    printf("%s ",str);
    for (int i = 0; i < 8; ++i) {
        printf("%x ",temp[i]);
    }
    printf("\n");
}
