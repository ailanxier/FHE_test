#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include <algorithm>
#include <iterator>
#include <util.h>

int main(int argc, char **argv){
    // 套接字连接初始化
    int server_sfd = socket_server_init();
    struct sockaddr_in peeraddr;
    socklen_t peerlen = sizeof(peeraddr);
    int server_connsfd;
    if((server_connsfd = accept(server_sfd, (struct sockaddr* )&peeraddr, &peerlen)) < 0)
        ERR_EXIT("server error: fail to be accepted by the client");
    print_words({"server: socket is accepted by client"});
    
    // 接收同态加密上下文，公钥和要计算的密文
    recv_file(server_connsfd, helib_server_context_fileName);
    std::ifstream helib_server_ifile(helib_server_context_fileName, std::fstream::in);
    helib::Context helib_server_context = helib::Context::readFrom(helib_server_ifile);
    helib::PubKey helib_server_pk = helib::PubKey::readFrom(helib_server_ifile, helib_server_context);
    helib::Ctxt helib_server_ctxt = helib::Ctxt::readFrom(helib_server_ifile, helib_server_pk);
    helib_server_ifile.close();
    // Print the security level
    print_words({"HElib: security level is", TOS(helib_server_context.securityLevel())}, 2);

    // 密文计算
    helib_server_ctxt.multiplyBy(helib_server_ctxt);
    helib_server_ctxt += helib_server_ctxt;
    helib::Ptxt<helib::BGV> ptxt(helib_server_context);
    
    // ptxt = [0] [1] [2] ... [nslots-2] [nslots-1]
    for (int i = 0; i < ptxt.size(); i++)
        ptxt[i] = 1;
    helib_server_ctxt.addConstant(ptxt);

    // 保存结果密文到文件
    std::ofstream helib_server_ofile(helib_server_result_filename, std::fstream::out | std::fstream::trunc);
    if(helib_server_ofile.is_open())
        helib_server_ctxt.writeTo(helib_server_ofile);
    else
        ERR_EXIT("server error: fail to open file to save ctxt");
    helib_server_ofile.close();

    // 发送保存结果密文的文件
    send_file(server_connsfd, helib_server_result_filename);
    print_words({"server: finish successfully"}, 1);
    return 0;
}