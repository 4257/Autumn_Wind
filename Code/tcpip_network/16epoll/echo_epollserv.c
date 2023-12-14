#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <arpa/inet.h>


#define BUF_SIZE 1024

void error_handing(char* message);
void prtfd(char* str,fd_set fd);
void prtepfd(int event_cnt,struct epoll_event * ev);

int main(int argc,char* argv[]){
    //服务器端套接字描述符
	int serv_sock;
    //客户端端套接字描述符
	int clnt_sock;

    //Buff
    char message[BUF_SIZE];
    int str_len;
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

    struct epoll_event event;
    struct epoll_event* ep_events;
    int epfd ,event_cnt;

#define EPOLL_SIZE 50
    epfd = epoll_create(EPOLL_SIZE);
    ep_events = malloc(sizeof(struct epoll_event)*BUF_SIZE);

    event.events = EPOLLIN;
    event.data.fd = serv_sock;
    epoll_ctl(epfd,EPOLL_CTL_ADD,serv_sock,&event);

    while(1){
        event_cnt = epoll_wait(epfd,ep_events,EPOLL_SIZE,-1);
        printf("event_cnt :%d\n",event_cnt);
        prtepfd(event_cnt,ep_events);
        //监视是否有待读取的数据
        if(event_cnt == -1){
            puts("epoll_wait() error!");
            break;
        }
        for (int i = 0; i < event_cnt; i++) {
            //查找发生状态变化的文件描述符（有接收数据的套接字）
            if(ep_events[i].data.fd == serv_sock){

                printf("index: %d ep_events server sockt :%d\n",i,ep_events[i].data.fd);
                prtepfd(event_cnt,ep_events);

                clnt_addr_size = sizeof(clnt_addr);
                clnt_sock = accept(serv_sock,(struct sockaddr*)&clnt_addr,&clnt_addr_size);
                event.data.fd = clnt_sock;
                event.events = EPOLLIN;
                epoll_ctl(epfd,EPOLL_CTL_ADD,clnt_sock,&event);

                prtepfd(event_cnt,ep_events);

                printf("connect client :%d \n",clnt_sock);
            }else{
                str_len = read(ep_events[i].data.fd,message,BUF_SIZE);
                if (str_len == 0){
                    epoll_ctl(epfd,EPOLL_CTL_DEL,ep_events[i].data.fd,NULL);
                    close(ep_events[i].data.fd);
                    printf("close client :%d \n",ep_events[i].data.fd);
                }else{
                    write(ep_events[i].data.fd,message, str_len);
                }
            }
        }
    }
	close(serv_sock);
    close(epfd);
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

void prtepfd(int event_cnt,struct epoll_event * ev){
    for (int i = 0; i < event_cnt+10; i++) {
        printf("%d ",ev[i].data.fd);
    }
    printf("\n");
}
