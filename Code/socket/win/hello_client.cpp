#include <WinSock2.h>
#include <iostream>

void ErrorHandling(const char* message);

int main(int argc, char* argv[])
{

    WSADATA wsaData;

    SOCKET hClntSock;
    SOCKADDR_IN servAddr;
    int strLen;
    char message[30];

    if (argc != 3)
    {
        printf("Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    //初始化套接字库
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ErrorHandling("WSAStartup() Error!");
    }
    //创建套接字
    hClntSock = socket(PF_INET, SOCK_STREAM, 0);
    if (hClntSock == INVALID_SOCKET) {
        ErrorHandling("socket() Error!");
    }
    memset(&servAddr,0,sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr(argv[1]);
    servAddr.sin_port = htons(atoi(argv[2]));

    printf("servAddr.sin_family: %d \n", servAddr.sin_family);
    printf("servAddr.sin_addr.s_addr: %d \n", servAddr.sin_addr.s_addr);
    printf("servAddr.sin_family: %d \n", servAddr.sin_port);
    //给创建的套接字分配IP和端口
    if (connect(hClntSock, (SOCKADDR*)&servAddr, sizeof(servAddr)) == SOCKET_ERROR) {
        ErrorHandling("bind() Error!");
    }

    strLen = recv(hClntSock,message,sizeof(message)-1,0);
    if (strLen == -1)
    {
        ErrorHandling("read() Error!");
    }
    printf("Message from server:%s\n",message);

    closesocket(hClntSock);

    WSACleanup();

    return 0;
}

void ErrorHandling(const char* message) {
    fputs(message, stderr);
    fputs("\n", stderr);
    exit(1);
}
