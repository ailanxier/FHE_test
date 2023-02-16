#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include <algorithm>
#include <iterator>
#include "util.h"
#include "HElib_setting.h"

int main(int argc, char **argv){
    print("-----------------------HElib-----------------------");
    // -------------------------------------
    // 客户端创建上下文
    print("client: Initialising context object ...");
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
    print_words({"client: security level is", TOS(client_context.securityLevel())}, 2);
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
    std::ofstream client_ofile(info_fileName, std::fstream::out | std::fstream::trunc);
    if(!client_ofile.is_open())
        ERR_EXIT("client error: fail to open file to save context");
    client_context.writeTo(client_ofile);
    client_pk.writeTo(client_ofile);
    client_ctxt.writeTo(client_ofile);
    client_ofile.close();
    
    // -------------------------------------
    // 服务器端恢复上下文，计算密文，保存结果
    std::ifstream server_ifile(info_fileName, std::fstream::in);
    helib::Context server_context = helib::Context::readFrom(server_ifile);
    helib::PubKey server_pk = helib::PubKey::readFrom(server_ifile, server_context);
    helib::Ctxt server_ctxt = helib::Ctxt::readFrom(server_ifile, server_pk);
    server_ifile.close();
    // Print the security level
    print_words({"server: security level is", TOS(server_context.securityLevel())}, 2);

    // 密文计算
    server_ctxt.multiplyBy(server_ctxt);
    server_ctxt += server_ctxt;
    helib::Ptxt<helib::BGV> ptxt(server_context);
    
    // ptxt = [0] [1] [2] ... [nslots-2] [nslots-1]
    for (int i = 0; i < ptxt.size(); i++)
        ptxt[i] = 1;
    server_ctxt.addConstant(ptxt);

    // 保存结果密文到文件
    std::ofstream server_ofile(result_filename, std::fstream::out | std::fstream::trunc);
    if(!server_ofile.is_open())
        ERR_EXIT("server error: fail to open file to save ctxt");
    server_ctxt.writeTo(server_ofile);
    server_ofile.close();

    // -------------------------------------
    // 客户端解密结果
    std::ifstream client_ifile(result_filename, std::fstream::in);
    helib::Ctxt result_ctxt = helib::Ctxt::readFrom(client_ifile, client_pk);
    // 将解密结果保存到明文中并打印
    helib::Ptxt<helib::BGV> ptxt_result(client_context);
    client_sk.Decrypt(ptxt_result, result_ctxt);
    std::cout << "Decrypted Result: " << ptxt_result << std::endl;
    
    print("client: finish successfully");
    return 0;
}