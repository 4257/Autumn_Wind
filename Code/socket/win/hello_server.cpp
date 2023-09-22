#include <WinSock2.h>
#include <iostream>

void ErrorHandling(const char* message);

int main(int argc,char* argv[])
{   

    WSADATA wsaData;
    
    SOCKET hServSock, hClntSock;
    SOCKADDR_IN servAddr, clntAddr;
    int szClntAddr;
    char message[] = "Hello World!";

    if (argc != 2)
    {
        printf("Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    //初始化套接字库
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ErrorHandling("WSAStartup() Error!");
    }
    //创建套接字
    hServSock = socket(PF_INET, SOCK_STREAM, 0);
    if (hServSock == INVALID_SOCKET) {
        ErrorHandling("socket() Error!");
    }
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(atoi(argv[1]));

    printf("servAddr.sin_family: %d \n", servAddr.sin_family);
    printf("servAddr.sin_addr.s_addr: %d \n", servAddr.sin_addr.s_addr);
    printf("servAddr.sin_family: %d \n", servAddr.sin_port);
    //给创建的套接字分配IP和端口
    if (bind(hServSock, (SOCKADDR*)&servAddr, sizeof(servAddr)) == SOCKET_ERROR) {
        ErrorHandling("bind() Error!");
    }
    //使用listen函数使创建的套接字成为服务端套接字
    if (listen(hServSock,5)==SOCKET_ERROR) {
        ErrorHandling("listen() Error!");
    }
    
    
    szClntAddr = sizeof(clntAddr);
    //accept函数手受理来自客户端的连接
    hClntSock = accept(hServSock,(SOCKADDR*)&clntAddr,&szClntAddr);
    if (hClntSock == INVALID_SOCKET)
    {
        ErrorHandling("accept() Error!");
    }

    send(hClntSock, message,sizeof(message),0);
    closesocket(hServSock);
    closesocket(hClntSock);

    WSACleanup();

    return 0;
}

void ErrorHandling(const char* message) {
    fputs(message, stderr);
    fputs("\n", stderr);
    exit(1);
}
