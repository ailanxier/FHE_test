#ifndef UTIL_SOCKET_H
#define UTIL_SOCKET_H

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <util_cout.h>
#include <util_string.h>
#include <general_setting.h>

#define CLIENT_PORT 5555
#define SERVER_PORT 5555
#define CLIENT_IP "127.0.0.1"
#define SERVER_IP INADDR_ANY


/**
 * @brief Client creates a socket and connects with the server.
 * @return a socket file descriptor to communicate with the server
 **/
int socket_client_init(){
    int client_sfd;
    if((client_sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        ERR_EXIT("client error: fail to build socket");

    print_words({"client: socket fd is", TOS(client_sfd)}, 2);
    struct sockaddr_in client_addr;
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(CLIENT_PORT);
    inet_aton(CLIENT_IP, &client_addr.sin_addr);
    bzero(&client_addr.sin_zero, sizeof client_addr.sin_zero);

    print_words({"client: connecting server"});
    // 客户端向指定的服务器和端口发送连接请求
    if(connect(client_sfd, (struct sockaddr* )&client_addr, sizeof(client_addr)) < 0)
        ERR_EXIT("client error: fail to connect server");
    
    return client_sfd;
}

/**
 * @brief Server creates a socket and 
 *        listens for requests from clients to establish a connection.
 * @return a socket file descriptor to be accepted by the client.
 **/
int socket_server_init(){
    int server_sfd;
    if((server_sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        ERR_EXIT("server error: fail to build socket");

    print_words({"server: socket fd is", TOS(server_sfd)}, 2);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = htonl(SERVER_IP);
    
    // 调用close(socket)（一般不会立即关闭而经历TIME_WAIT的过程）后想继续重用该socket
    // int reuse=1;
    // if(setsockopt(server_sfd, SOL_SOCKET, SO_REUSEADDR, (const char*)& reuse, sizeof(int)) < 0)
    //     ERR_EXIT("setsockopt err");

    // 服务器端将套接字与特定的 IP 地址和端口绑定
    if(bind(server_sfd, (struct sockaddr* )&server_addr, sizeof(server_addr)) < 0)
        ERR_EXIT("server error: fail to bind socket");
    print_words({"server: binding socket"});

    // 服务器端让套接字进入被动监听状态
    if(listen(server_sfd, SOMAXCONN) < 0)
        ERR_EXIT("server error: fail to listen request");
    print_words({"server: listening socket"});
    return server_sfd;
}

/**
 * @brief Send a file to the server
 * @param sfd a socket file descriptor to communicate with the server
 * @param file_name name of the file to be sent
 **/
void send_file(int sfd, const char* file_name){
    print_one_star_line();
    print_words({"start sending file <", file_name, ">"}, 2);
    int length = 0;
    char buf[SEND_BUF_MAXSIZE];

    // 只读方式打开
    FILE *fp = fopen(file_name, "r");
    if(NULL == fp)
        ERR_EXIT("send error: file does not exist");
    else{
        // 循环发送数据,直到文件读完为止
        while((length = fread(buf, sizeof(char), sizeof(buf), fp)) > 0){
            buf[length] = '\0';
            // 发送数据包的大小
            if(send(sfd, &length, sizeof(length), 0) < 0)
                ERR_EXIT("send error: fail to send length of the ciphertext");
            // 发送数据包的内容
            if(send(sfd, buf, length, 0) < 0)
                ERR_EXIT("send error: fail to send the ciphertext");
            print_words({"sending: size of the sent ciphertext: ", TOS(length)}, 2);
            print_words({"sending: the sent ciphertext is:", buf}, 2);
            print_one_star_line();
        }
        // 读取文件完成, 发送 0 数据包
        length = 0;
        send(sfd, &length, sizeof(length), 0);
    }
    // 关闭文件    
    fclose(fp);
    print_words({"send file <", file_name, "> successfully"}, 2);
    print_one_star_line();
}

/**
 * @brief Receive a file through connsfd
 * @param connsfd a socket file descriptor to receive file
 * @param file_name name of the file to be saved
 **/
void recv_file(int connsfd, const char* file_name){
    print_one_star_line();
    print_words({"recv: start receiving file"}, 1);
    char buf[HElib_RECV_BUF_MINSIZE];
    int length = 0;
    // 以可写方式创建文件
    FILE *fp = fopen(file_name, "w");
    if(fp == NULL)
        ERR_EXIT("recv error: fail to open file");
    while(true){
        // 接收数据包的大小
        if(recv(connsfd, &length, sizeof(length), MSG_WAITALL) < 0)
            ERR_EXIT("recv error: fail to receive length of the ciphertext");
        // 当长度为0时,接收完毕,退出
        if(length == 0)
            break;
        // 接收数据包的内容
        if(recv(connsfd, buf, length, MSG_WAITALL) < 0)
            ERR_EXIT("recv error: fail to receive name of the file");
        buf[length] = '\0';
        print_words({"receiving: the length of received ciphertext is", TOS(length)}, 2);
        print_words({"receiving: the received ciphertext is:", buf}, 2);
        print_one_star_line();
        if(fwrite(buf, sizeof(char), length, fp) < length)
            ERR_EXIT("recv error: fail to save ciphertext to file");
    }
    fclose(fp);
    print_words({"recv: receive file successfully"}, 1);
    print_one_star_line();
}

#endif

// // 发送文件名
// int send_filename(int sfd,char* filename)
// {
//     int len=0;
//     char buf[128] = {0};

//     strcpy(buf,filename);
//     len = strlen(buf);
//     //printf("%d\n",len);
//     send(sfd,&len,sizeof(len),0);
//     send(sfd,buf,len,0);
// }


// //接收文件名,
// int recv_filename(int conn,char** name)
// {
//     int file_len =0;
//     int r=0;

//     if((r=recv(conn,&file_len,sizeof(file_len),MSG_WAITALL)) <= 0)
//         exit(1);
//     if((r = recv(conn,(*name),file_len,MSG_WAITALL)) <= 0)
//         exit(1);
//     (*name)[file_len] = 0;  // 接收到文件名后加/0
//     //printf("// %s //\n",*name);

//     return  0;
// }