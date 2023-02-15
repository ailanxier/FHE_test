#include "OpenFHE_setting.h"
#include "util.h"

using namespace lbcrypto;

int main(int argc, char **argv){
    // 套接字连接初始化
    int server_sfd = socket_server_init();
    struct sockaddr_in peeraddr;
    socklen_t peerlen = sizeof(peeraddr);
    int server_connsfd;
    if((server_connsfd = accept(server_sfd, (struct sockaddr* )&peeraddr, &peerlen)) < 0)
        ERR_EXIT("server error: fail to be accepted by the client");
    print("server: socket is accepted by client");
    
    // 接收同态加密上下文，公钥和要计算的密文
    recv_file(server_connsfd, server_recv_fileName);
    std::ifstream server_ifile(server_recv_fileName, std::ios::in | std::ios::binary);
    if(!server_ifile.is_open()) 
        ERR_EXIT("server error: fail to open file to load context");

    // 从文件中解密上下文，公钥，评估密钥，密文
    CryptoContext<DCRTPoly> context;
    DeserializeFromStream(server_ifile, context, SerType::BINARY);
    print("server: the cryptocontext has been deserialized");

    PublicKey<DCRTPoly> pk;
    DeserializeFromStream(server_ifile, pk, SerType::BINARY);
    print("server: the public key has been deserialized");

    if (!context->DeserializeEvalMultKey(server_ifile, SerType::BINARY)) 
        ERR_EXIT("Could not deserialize the eval mult key file");
    print("server: the eval mult keys has been deserialized");

    Ciphertext<DCRTPoly> ctxt1, ctxt2, ctxt3;
    DeserializeFromStream(server_ifile, ctxt1, SerType::BINARY);
    DeserializeFromStream(server_ifile, ctxt2, SerType::BINARY);
    DeserializeFromStream(server_ifile, ctxt3, SerType::BINARY);
    server_ifile.close();
    print("server: three ciphertexts have been deserialized");

    // Homomorphic additions
    auto ctxt_add_12 = context->EvalAdd(ctxt1, ctxt2); 
    auto ctxt_add_123 = context->EvalAdd(ctxt_add_12, ctxt3); 
    // Homomorphic multiplications
    auto ctxt_mul_12 = context->EvalMult(ctxt1, ctxt2);   
    auto ctxt_mul_123 = context->EvalMult(ctxt_mul_12, ctxt3);   

    // 保存结果密文到文件
    std::ofstream server_ofile(server_result_filename, std::ios::out | std::ios::binary);
    if(!server_ofile.is_open())
        ERR_EXIT("server error: fail to open file to save ctxt");
    SerializeToStream(server_ofile, ctxt_add_123, SerType::BINARY);
    SerializeToStream(server_ofile, ctxt_mul_123, SerType::BINARY);
    server_ofile.close();
    print("server: results have been serialized");
    
    // 发送保存结果密文的文件
    send_file(server_connsfd, server_result_filename);
    print("server: finish successfully");
    return 0;
}