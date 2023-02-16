#include "OpenFHE_setting.h"
#include "util.h"

// OpenFHE 的命名空间
using namespace lbcrypto;

int main(int argc, char **argv){
    print("---------------------OpenFHE---------------------");
    print("client: Initialising context object ...");
    // 客户端设置加密上下文参数
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetPlaintextModulus(65537);

    CryptoContext<DCRTPoly> client_context = GenCryptoContext(parameters);
    // Enable features that you wish to use
    client_context->Enable(PKE);
    client_context->Enable(KEYSWITCH);
    client_context->Enable(LEVELEDSHE);

    // 将加密上下文写入文件
    std::ofstream client_ofile(info_fileName, std::ios::out | std::ios::binary);
    if(!client_ofile.is_open()) 
        ERR_EXIT("client error: fail to open file to save context");
    SerializeToStream(client_ofile, client_context, SerType::BINARY);
    print("client: the cryptocontext has been serialized");

    // 生成公私密钥
    KeyPair<DCRTPoly> client_keyPair;
    client_keyPair = client_context->KeyGen();    
    SerializeToStream(client_ofile, client_keyPair.publicKey, SerType::BINARY);
    print("client: the public key has been serialized");
    
    // Generate the relinearization key
    client_context->EvalMultKeyGen(client_keyPair.secretKey);
    // Serialize the relinearization (evaluation) key for homomorphic multiplication
    if (!client_context->SerializeEvalMultKey(client_ofile, SerType::BINARY))
        ERR_EXIT("client error: fail to write serialization of the eval mult keys");
    print("client: the eval mult keys have been serialized");

    std::vector<int64_t> v1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext client_ptxt1  = client_context->MakePackedPlaintext(v1);
    std::vector<int64_t> v2 = {10, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext client_ptxt2  = client_context->MakePackedPlaintext(v2);
    std::vector<int64_t> v3 = {10, 20, 30, 40, 50, 60, 70, 80, 90, 10, 11, 12};
    Plaintext client_ptxt3  = client_context->MakePackedPlaintext(v3);

    // The encoded vectors are encrypted
    auto client_ctxt1 = client_context->Encrypt(client_keyPair.publicKey, client_ptxt1);
    auto client_ctxt2 = client_context->Encrypt(client_keyPair.publicKey, client_ptxt2);
    auto client_ctxt3 = client_context->Encrypt(client_keyPair.publicKey, client_ptxt3);
    SerializeToStream(client_ofile, client_ctxt1, SerType::BINARY);
    SerializeToStream(client_ofile, client_ctxt2, SerType::BINARY);
    SerializeToStream(client_ofile, client_ctxt3, SerType::BINARY);
    client_ofile.close();
    print("client: three ciphertexts have been serialized");
    // std::cout << "Plaintext #1: " << ptxt1 << std::endl;
    
    // ------------------------------------------
    // 服务器端处理
    std::ifstream server_ifile(info_fileName, std::ios::in | std::ios::binary);
    if(!server_ifile.is_open()) 
        ERR_EXIT("server error: fail to open file to load context");

    // 从文件中解密上下文，公钥，评估密钥，密文
    CryptoContext<DCRTPoly> server_context;
    DeserializeFromStream(server_ifile, server_context, SerType::BINARY);
    print("server: the cryptocontext has been deserialized");

    PublicKey<DCRTPoly> server_pk;
    DeserializeFromStream(server_ifile, server_pk, SerType::BINARY);
    print("server: the public key has been deserialized");

    if (!server_context->DeserializeEvalMultKey(server_ifile, SerType::BINARY)) 
        ERR_EXIT("Could not deserialize the eval mult key file");
    print("server: the eval mult keys has been deserialized");

    Ciphertext<DCRTPoly> server_ctxt1, server_ctxt2, server_ctxt3;
    DeserializeFromStream(server_ifile, server_ctxt1, SerType::BINARY);
    DeserializeFromStream(server_ifile, server_ctxt2, SerType::BINARY);
    DeserializeFromStream(server_ifile, server_ctxt3, SerType::BINARY);
    server_ifile.close();
    print("server: three ciphertexts have been deserialized");

    // Homomorphic additions
    auto server_ctxt_add_12 = server_context->EvalAdd(server_ctxt1, server_ctxt2); 
    auto server_ctxt_add_123 = server_context->EvalAdd(server_ctxt_add_12, server_ctxt3); 
    // Homomorphic multiplications
    auto server_ctxt_mul_12 = server_context->EvalMult(server_ctxt1, server_ctxt2);   
    auto server_ctxt_mul_123 = server_context->EvalMult(server_ctxt_mul_12, server_ctxt3);   

    // 保存结果密文到文件
    std::ofstream server_ofile(result_filename, std::ios::out | std::ios::binary);
    if(!server_ofile.is_open())
        ERR_EXIT("server error: fail to open file to save ctxt");
    SerializeToStream(server_ofile, server_ctxt_add_123, SerType::BINARY);
    SerializeToStream(server_ofile, server_ctxt_mul_123, SerType::BINARY);
    server_ofile.close();
    print("server: results have been serialized");

    // ------------------------------------------
    // 客户端解密
    std::ifstream client_ifile(result_filename, std::ios::in | std::ios::binary);
    Ciphertext<DCRTPoly> result_add_ctxt, result_mul_ctxt;
    DeserializeFromStream(client_ifile, result_add_ctxt, SerType::BINARY);
    DeserializeFromStream(client_ifile, result_mul_ctxt, SerType::BINARY);
    client_ifile.close();
    print("client: result have been deserialized");

    // 将解密结果保存到明文中并打印
    Plaintext client_result_add_ptxt, client_result_mul_ptxt;
    client_context->Decrypt(client_keyPair.secretKey, result_add_ctxt, &client_result_add_ptxt);
    client_context->Decrypt(client_keyPair.secretKey, result_mul_ctxt, &client_result_mul_ptxt);
    std::cout << "#1 + #2 + #3: " << client_result_add_ptxt << std::endl;
    std::cout << "#1 * #2 * #3: " << client_result_mul_ptxt << std::endl;
    print("client: finish successfully");
    return 0;
}