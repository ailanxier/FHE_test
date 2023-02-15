#include "OpenFHE_setting.h"
#include "util.h"

// OpenFHE 的命名空间
using namespace lbcrypto;

int main(int argc, char **argv){
    print("---------------------OpenFHE---------------------");
    // 创建 socket 并与服务器端连接
    int client_sfd = socket_client_init();
    print("client: Initialising context object ...");

    //设置加密上下文参数
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetPlaintextModulus(65537);

    CryptoContext<DCRTPoly> context = GenCryptoContext(parameters);
    // Enable features that you wish to use
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);

    // 将加密上下文写入文件
    std::ofstream client_ofile(client_send_fileName, std::ios::out | std::ios::binary);
    if(!client_ofile.is_open()) 
        ERR_EXIT("client error: fail to open file to save context");
    SerializeToStream(client_ofile, context, SerType::BINARY);
    print("client: the cryptocontext has been serialized");

    // 生成公私密钥
    KeyPair<DCRTPoly> keyPair;
    keyPair = context->KeyGen();    
    SerializeToStream(client_ofile, keyPair.publicKey, SerType::BINARY);
    print("client: the public key has been serialized");
    
    // Generate the relinearization key
    context->EvalMultKeyGen(keyPair.secretKey);
    // Serialize the relinearization (evaluation) key for homomorphic multiplication
    if (!context->SerializeEvalMultKey(client_ofile, SerType::BINARY))
        ERR_EXIT("client error: fail to write serialization of the eval mult keys");
    print("client: the eval mult keys have been serialized");

    std::vector<int64_t> v1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext ptxt1         = context->MakePackedPlaintext(v1);
    std::vector<int64_t> v2 = {10, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext ptxt2         = context->MakePackedPlaintext(v2);
    std::vector<int64_t> v3 = {10, 20, 30, 40, 50, 60, 70, 80, 90, 10, 11, 12};
    Plaintext ptxt3         = context->MakePackedPlaintext(v3);

    // The encoded vectors are encrypted
    auto ctxt1 = context->Encrypt(keyPair.publicKey, ptxt1);
    auto ctxt2 = context->Encrypt(keyPair.publicKey, ptxt2);
    auto ctxt3 = context->Encrypt(keyPair.publicKey, ptxt3);
    SerializeToStream(client_ofile, ctxt1, SerType::BINARY);
    SerializeToStream(client_ofile, ctxt2, SerType::BINARY);
    SerializeToStream(client_ofile, ctxt3, SerType::BINARY);
    client_ofile.close();
    print("client: three ciphertexts have been serialized");
    // std::cout << "Plaintext #1: " << ptxt1 << std::endl;
    
    // 发送上下文，公钥，评估密钥，密文给 server
    send_file(client_sfd, client_send_fileName);

    // 接收结果密文
    recv_file(client_sfd, client_result_filename);
    close(client_sfd);
    std::ifstream client_ifile(client_result_filename, std::ios::in | std::ios::binary);
    Ciphertext<DCRTPoly> result_add_ctxt, result_mul_ctxt;
    DeserializeFromStream(client_ifile, result_add_ctxt, SerType::BINARY);
    DeserializeFromStream(client_ifile, result_mul_ctxt, SerType::BINARY);
    client_ifile.close();
    print("client: result have been deserialized");

    // 将解密结果保存到明文中并打印
    Plaintext result_add_ptxt, result_mul_ptxt;
    context->Decrypt(keyPair.secretKey, result_add_ctxt, &result_add_ptxt);
    context->Decrypt(keyPair.secretKey, result_mul_ctxt, &result_mul_ptxt);
    std::cout << "#1 + #2 + #3: " << result_add_ptxt << std::endl;
    std::cout << "#1 * #2 * #3: " << result_mul_ptxt << std::endl;
    print("client: finish successfully");
    return 0;
}