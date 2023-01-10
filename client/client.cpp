#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include <algorithm>
#include <iterator>
#include <util_socket.h>
#include <util_cout.h>
#include <util_string.h>
#include <HElib_setting.h>

int main(int argc, char **argv){
    std::ofstream client_send_file(send_file_name, std::fstream::out | std::fstream::trunc);
    client_send_file << "client sends a file";
    client_send_file.close();

    print_words({"client: save context to file"}, 1);
    
    // 创建 socket 并与服务器端连接
    int client_sfd = socket_client_init();
    send_file(client_sfd, send_file_name);
    
    // 把用户信息密文传输至服务器
    sleep(1);
    print_words({"client: start sending ciphertexts"}, 1);
    print_one_star_line();
    for(int i = 1; i <= 4; i++){
        std::ostringstream oss;
        std::string send_ciphertext = "test ciphertext - " + TOS(i);
        oss << send_ciphertext;
        print_words({"client: Size of the sent ciphertext: ", TOS(send_ciphertext.size())}, 2);
        print_words({"client: the sent ciphertext is:", send_ciphertext}, 2);
        print_one_star_line();
        
        if (send(client_sfd, oss.str().c_str(), oss.str().size(), 0) < 0)           
            ERR_EXIT("client error: fail to send ciphertext to server");
        
        // 发送下一次数据之前把oss对象清空，不然会出现"数据重复"
        oss.str("");
        sleep(1);
    }
    print_words({"client: start receiving ciphertexts"}, 1);
    print_one_star_line();
    for(int i = 1; i <= 4; i++){
        char *buffer = new char[HElib_RECV_BUF_MAXSIZE];
        int bytes_read = recv(client_sfd, buffer, HElib_RECV_BUF_MAXSIZE, 0);
        if(bytes_read < 0)
            ERR_EXIT("client error: fail to receive ciphertext from server");
        std::string sBuffer((const char*)buffer, bytes_read);
        print_words({"client: size of the received ciphertext: ", TOS(bytes_read)}, 2);
        print_words({"client: the received ciphertext is:", buffer}, 2);
        delete buffer;
        print_one_star_line();
    }
    close(client_sfd);
    print_words({"client: finish successfully"}, 1);
    return 0;
}