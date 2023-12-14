#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>


int main(int argc,char* argv[]){

    int tcp_sock,udp_sock;
    int sock_type;
    socklen_t optlen;

    optlen = sizeof(sock_type);

    tcp_sock = socket(PF_INET,SOCK_STREAM,0);
    udp_sock = socket(PF_INET,SOCK_DGRAM,0);
    printf("SOCK_STREAM: %d\n",SOCK_STREAM);
    printf("SOCK_DGRAM: %d\n",SOCK_DGRAM);

    getsockopt(tcp_sock,SOL_SOCKET,SO_TYPE,(void*)&sock_type,&optlen);
    printf("Socket type tcp: %d\n",sock_type);
    getsockopt(udp_sock,SOL_SOCKET,SO_TYPE,(void*)&sock_type,&optlen);
    printf("Socket type udp: %d\n",sock_type);

    int snd_buf,rcv_buf;
    getsockopt(tcp_sock,SOL_SOCKET,SO_SNDBUF,(void*)&snd_buf,&optlen);
    printf("Socket snd_buf tcp: %d\n",snd_buf);
    getsockopt(tcp_sock,SOL_SOCKET,SO_RCVBUF,(void*)&rcv_buf,&optlen);
    printf("Socket rcv_buf tcp: %d\n",snd_buf);

    int rsnd_buf = 1024 * 10,rrcv_buf = 1024 * 10;
    setsockopt(tcp_sock,SOL_SOCKET,SO_SNDBUF,(void*)&rsnd_buf,optlen);
    setsockopt(tcp_sock,SOL_SOCKET,SO_SNDBUF,(void*)&rrcv_buf,optlen);

    getsockopt(tcp_sock,SOL_SOCKET,SO_SNDBUF,(void*)&snd_buf,&optlen);
    printf("Socket snd_buf tcp: %d\n",snd_buf);
    getsockopt(tcp_sock,SOL_SOCKET,SO_RCVBUF,(void*)&rcv_buf,&optlen);
    printf("Socket rcv_buf tcp: %d\n",snd_buf);
    return 0;

}
