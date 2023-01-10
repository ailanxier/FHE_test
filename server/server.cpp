#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include <algorithm>
#include <iterator>
#include <util_cout.h>
#include <util_socket.h>

int main(int argc, char **argv){
    // 套接字连接初始化
    int server_sfd = socket_server_init();

    struct sockaddr_in peeraddr;
    socklen_t peerlen = sizeof(peeraddr);
    int server_connsfd;
    if((server_connsfd = accept(server_sfd, (struct sockaddr* )&peeraddr, &peerlen)) < 0)
        ERR_EXIT("server error: fail to be accepted by the client");
    print_words({"server: socket is accepted by client"});
    
    // 接收含有FHEcontext和publicKey的iotest.txt文件
    recv_file(server_connsfd, recv_file_name);

    sleep(1);    
    // 密文数组
    // Ctxt* ctxt[4];
    // for (int i = 0; i < 4; i++)
    //     ctxt[i] = new Ctxt(publicKey);
    print_words({"server: start receiving ciphertexts"}, 1);
    char *ctxt_buf[4];
    for (int i = 0; i < 4; i++){        
        char* buf = new char[HElib_RECV_BUF_MAXSIZE];
        ctxt_buf[i] = new char[HElib_RECV_BUF_MAXSIZE];
        int bytes_read = recv(server_connsfd, buf, HElib_RECV_BUF_MAXSIZE, 0);
        if(bytes_read < 0)
            ERR_EXIT("server error: fail to receive ciphertext from client");

        print_words({"server: size of the received ciphertext: ", TOS(bytes_read)}, 2);
        print_words({"server: the received ciphertext is:", buf}, 2);
        print_one_star_line();
        stpcpy(ctxt_buf[i], buf);
        delete buf;
    }
    print_words({"server: start sending result ciphertexts"}, 1);
    print_one_star_line();
    // 对密文进行运算

    // 把用户信息密文返回到客户端
    for (int i = 0; i < 4; i++){
        print_words({"server: size of the result ciphertext: ", TOS(strlen(ctxt_buf[i]))}, 2);
        print_words({"server: the result ciphertext is:", ctxt_buf[i]}, 2);
        print_one_star_line();

        if (send(server_connsfd, ctxt_buf[i], strlen(ctxt_buf[i]), 0) < 0)
            ERR_EXIT("server error: fail to send result to client");
        sleep(1);
    }
    print_words({"server: finish successfully"}, 1);
    return 0;
}