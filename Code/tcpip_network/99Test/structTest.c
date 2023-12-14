#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc,char* argv[]){
    struct sockaddr_in sock_in;
    struct sockaddr* sockadr;
    struct in_addr in_adr;

    memset(&sock_in,0,sizeof(sock_in));
    sock_in.sin_family = AF_INET;
    sock_in.sin_addr.s_addr = inet_addr("127.10.10.10");
    sock_in.sin_port = htons(atoi("9000"));

    printf("%hu\n",sock_in.sin_family);
    printf("%x\n",sock_in.sin_port);
    printf("%x\n",sock_in.sin_addr.s_addr);
    printf("%s\n",sock_in.sin_zero);

    sockadr = (struct sockaddr*)&sock_in;
    printf("%hu\n",sockadr->sa_family);
    for (int i = 0;i<6; i++) {
        printf("%x",sockadr->sa_data[i]);
    }
    printf("\n");

    in_adr.s_addr=inet_addr("127.10.10.10");
    printf("%x\n",in_adr.s_addr);
    printf("%x\n", inet_addr("0x7f.0.0.0x1"));
//    printf("%lu\n",sizeof(sock_in));

    short ord = 0x1234;
    printf("%x\n",*((char*)&ord + 0));
    printf("%x\n",*((char*)&ord + 1));

    short ord2 = htons(ord);
    printf("%x\n",*((char*)&ord2 + 0));
    printf("%x\n",*((char*)&ord2 + 1));



}
