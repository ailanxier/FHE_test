#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include <algorithm>
#include <iterator>
#include "util.h"
#include "HElib_setting.h"

int main(int argc, char **argv){
    // 创建 socket 并与服务器端连接
    int client_sfd = socket_client_init();
    print("client-HElib: Initialising context object ...");
    // Plaintext prime modulus
    unsigned long p = 4999;
    // Cyclotomic polynomial - defines phi(m)
    unsigned long m = 32109;
    // Hensel lifting (default = 1)
    unsigned long r = 1;
    // Number of bits of the modulus chain
    unsigned long bits = 500;
    // Number of columns of Key-Switching matrix (default = 2 or 3)
    unsigned long c = 2;
    helib::Context client_context = helib::ContextBuilder<helib::BGV>()
                                .m(m)
                                .p(p)
                                .r(r)
                                .bits(bits)
                                .c(c)
                                .build();
    // Print the security level
    print_words({"HElib: security level is", TOS(client_context.securityLevel())}, 2);
    helib::SecKey client_sk(client_context);
    // Generate the secret key
    client_sk.GenSecKey();
    // Compute key-switching matrices that we need
    helib::addSome1DMatrices(client_sk);
    // Public key management
    const helib::PubKey& client_pk = client_sk;
    // Get the EncryptedArray of the context
    // const helib::EncryptedArray& ea = client_context.getEA();
    // Get the number of slot (phi(m))
    // long nslots = ea.size();
    // Create a vector of long with nslots elements
    helib::Ptxt<helib::BGV> client_ptxt(client_context);
    // Set it with numbers 0..nslots - 1
    // ptxt = [0] [1] [2] ... [nslots-2] [nslots-1]
    for (int i = 0; i < client_ptxt.size(); i++)
        client_ptxt[i] = i;
    // Create a ciphertext object
    helib::Ctxt client_ctxt(client_pk);
    // Encrypt the plaintext using the public_key
    client_pk.Encrypt(client_ctxt, client_ptxt);    
    // 保存加密上下文、公钥和要计算的密文到文件中
    print("client: sending context to server ...", 1, NO_STAR_LINE);
    std::ofstream client_ofile(client_send_fileName, std::fstream::out | std::fstream::trunc);
    if(client_ofile.is_open()){
        client_context.writeTo(client_ofile);
        client_pk.writeTo(client_ofile);
        client_ctxt.writeTo(client_ofile);
    }else
        ERR_EXIT("client error: fail to open file to save context");
    client_ofile.close();
    
    send_file(client_sfd, client_send_fileName);
    // 接收结果密文
    recv_file(client_sfd, client_result_filename);
    close(client_sfd);
    std::ifstream client_ifile(client_result_filename, std::fstream::in);
    helib::Ctxt result_ctxt = helib::Ctxt::readFrom(client_ifile, client_pk);
    // 将解密结果保存到明文中并打印
    helib::Ptxt<helib::BGV> ptxt_result(client_context);
    client_sk.Decrypt(ptxt_result, result_ctxt);
    std::cout << "Decrypted Result: " << ptxt_result << std::endl;
    
    print("client: finish successfully");
    return 0;
}