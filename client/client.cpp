#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include <algorithm>
#include <iterator>
#include <util.h>
#include <HElib_setting.h>

int main(int argc, char **argv){
    // 创建 socket 并与服务器端连接
    int client_sfd = socket_client_init();
    print_words({"client-HElib: Initialising context object ..."}, 1);
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
    helib::Context helib_client_context = helib::ContextBuilder<helib::BGV>()
                                .m(m)
                                .p(p)
                                .r(r)
                                .bits(bits)
                                .c(c)
                                .build();
    // Print the security level
    print_words({"HElib: security level is", TOS(helib_client_context.securityLevel())}, 2);
    helib::SecKey helib_client_sk(helib_client_context);
    // Generate the secret key
    helib_client_sk.GenSecKey();
    // Compute key-switching matrices that we need
    helib::addSome1DMatrices(helib_client_sk);
    // Public key management
    const helib::PubKey& helib_client_pk = helib_client_sk;
    // Get the EncryptedArray of the context
    const helib::EncryptedArray& ea = helib_client_context.getEA();
    // Get the number of slot (phi(m))
    long nslots = ea.size();
    // Create a vector of long with nslots elements
    helib::Ptxt<helib::BGV> ptxt(helib_client_context);
    // Set it with numbers 0..nslots - 1
    // ptxt = [0] [1] [2] ... [nslots-2] [nslots-1]
    for (int i = 0; i < ptxt.size(); i++)
        ptxt[i] = i;
    // Create a ciphertext object
    helib::Ctxt ctxt(helib_client_pk);
    // Encrypt the plaintext using the public_key
    helib_client_pk.Encrypt(ctxt, ptxt);    
    // 保存加密上下文、公钥和要计算的密文到文件中
    print_words({"client: sending context to server ..."}, 1, NO_STAR_LINE);
    std::ofstream helib_client_ofile(helib_client_context_fileName, std::fstream::out | std::fstream::trunc);
    if(helib_client_ofile.is_open()){
        helib_client_context.writeTo(helib_client_ofile);
        helib_client_pk.writeTo(helib_client_ofile);
        ctxt.writeTo(helib_client_ofile);
    }else
        ERR_EXIT("client error: fail to open file to save context");
    helib_client_ofile.close();
    
    send_file(client_sfd, helib_client_context_fileName);
    // 接收结果密文
    recv_file(client_sfd, helib_client_result_filename);
    close(client_sfd);
    std::ifstream helib_client_ifile(helib_client_result_filename, std::fstream::in);
    helib::Ctxt helib_result_ctxt = helib::Ctxt::readFrom(helib_client_ifile, helib_client_pk);
    // 将解密结果保存到明文中并打印
    helib::Ptxt<helib::BGV> ptxt_result(helib_client_context);
    helib_client_sk.Decrypt(ptxt_result, helib_result_ctxt);
    std::cout << "Decrypted Result: " << ptxt_result << std::endl;
    
    print_words({"client: finish successfully"}, 1);
    return 0;
}