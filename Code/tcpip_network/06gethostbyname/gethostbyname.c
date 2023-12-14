#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>

int main(int argc,char* argv[]){

    struct hostent *host;
    if (argc != 2) {
        printf("Usage: %s <addr>\n",argv[0]);
        exit(1);
    }
    //通过域名获取IP地址
    host = gethostbyname(argv[1]);
    printf("h_name:%s\n",host->h_name);
    for (int i = 0; host->h_aliases[i]; ++i) {
        printf("h_aliases %d :%s\n",i+1,host->h_aliases[i]);
    }
    printf("h_addrtype:%s\n",(host->h_addrtype == AF_INET)?"AF_INET":"AF_INET6");
    printf("h_length:%d\n",host->h_length);
    for (int i = 0;host->h_addr_list[i]; ++i) {
        printf("h_addr_list %d :%s\n",i+1, inet_ntoa(*(struct in_addr*)host->h_addr_list[i]));
    }
    return 0;
}
