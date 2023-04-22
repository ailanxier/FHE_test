#pragma once

#include "OpenFHE_setting.h"
#include "protobuf_parser.h"
#include "util.h"
#include <random>
#include <chrono>
#define NOT_NEG_MOD(num) (((num) % ptxt_mod + ptxt_mod) % ptxt_mod)

int dataLen, dataNum, frontLen;
CryptoContext<DCRTPoly> client_context, server_context;
CCParams<CryptoContextBGVRNS> parameters;
KeyPair<DCRTPoly> client_keyPair;
PublicKey<DCRTPoly> server_pk;
vector<vector<dataType>> data;
vector<Ciphertext<DCRTPoly>> server_ctxts;
vector<Plaintext> client_result_ptxts;
Root msg;
int maxLevel = 0;
bool isAllCorrect;
int muldepth = 0;
dataType ptxt_mod = 1;
std::fstream info_fstream, result_fstream;
// std::chrono::_V2::system_clock::time_point start;

inline void getTime(){ 
    // auto end = std::chrono::high_resolution_clock::now();
    // auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    // start = end;
    // Print_words({(string)COUT_RED + "use time: ", ToStr(duration.count()), "ms" + (string)(COUT_END_COLOR)}, 1, NO_STAR_LINE);
}
 
// Homomorphic context environment configuration for the client
inline void client_init_context(char* path){
    std::ifstream data_ifile(path, std::ios::in | std::ios::binary);
    if(!data_ifile.is_open()) 
        ERROR_EXIT("client error: fail to open data file");
    msg.ParseFromIstream(&data_ifile);
    Print("client: Initialising context object ...");
    Message2FHEParameters(msg, parameters, client_context, client_keyPair);
    muldepth = parameters.GetMultiplicativeDepth();
    ptxt_mod = client_context->GetEncodingParams()->GetPlaintextModulus();
    Print_words({"muldepth =", ToStr(muldepth), 
        "DigitSize =", ToStr(parameters.GetDigitSize()), 
        "Kstech =", ToStr(parameters.GetKeySwitchTechnique()),
        "RingDim =", ToStr(client_context->GetRingDimension())}, 2);
    
    // Write the encrypted context, keys except secretKey into a file
    SerializeToStream(info_fstream, client_context, SerType::BINARY);
    //Print("client: the cryptocontext has been serialized");

    SerializeToStream(info_fstream, client_keyPair.publicKey, SerType::BINARY);
    //Print("client: the public key has been serialized");

    // Serialize the relinearization (evaluation) key for homomorphic multiplication
    if (!client_context->SerializeEvalMultKey(info_fstream, SerType::BINARY))
        ERROR_EXIT("client error: fail to write serialization of the eval mult keys");
    //Print("client: the eval mult keys have been serialized");

    // Serialize the rotation key for homomorphic rotation
    if (msg.param().rotateindexes_size() > 0 && !client_context->SerializeEvalAutomorphismKey(info_fstream, SerType::BINARY))
        ERROR_EXIT("client error: fail to write serialization of the rotation keys");
    Print("client: the rotation keys have been serialized");
}

// Encrypt the original information on the client side and write it into a file
inline void client_encrypt_data(){
    auto alldataList = msg.evaldata().alldatalists();
    dataLen = client_context->GetRingDimension();
    dataNum = alldataList.size();
    if(dataNum == 0) exit(0);
    frontLen = 0;
    maxLevel = 0;
    data.resize(dataNum, vector<dataType>(dataLen));
    for(int i = 0; i < dataNum; i++){
        auto dataList = alldataList[i].datalist();
        int j = 0;
        for(auto num : dataList){
            data[i][j++] = NOT_NEG_MOD(num);
            if(j >= dataLen) break;
        }
        frontLen = std::max(frontLen, j);
    }
    for(int i = 0; i < dataNum; i++){
        auto client_ptxt = client_context->MakePackedPlaintext(data[i]);
        auto client_ctxt = client_context->Encrypt(client_keyPair.publicKey, client_ptxt);
        SerializeToStream(info_fstream, client_ctxt, SerType::BINARY);
    }
    Print("client: ciphertexts have been serialized");
    // Set the file stream back to the beginning of the file.
    info_fstream.seekp(std::ios::beg);
}

// The server recovers the context environment and ciphertext from the file 
inline void server_init_context(){
    DeserializeFromStream(info_fstream, server_context, SerType::BINARY);
    //Print("server: the cryptocontext has been deserialized");
    DeserializeFromStream(info_fstream, server_pk, SerType::BINARY);
    //Print("server: the public key has been deserialized");

    if (!server_context->DeserializeEvalMultKey(info_fstream, SerType::BINARY)) 
        ERROR_EXIT("Could not deserialize the eval mult key file");
    //Print("server: the eval mult keys has been deserialized");
    if (msg.param().rotateindexes_size() > 0 && !server_context->DeserializeEvalAutomorphismKey(info_fstream, SerType::BINARY)) 
        ERROR_EXIT("Could not deserialize the rotation keys file");
    //Print("server: the rotation keys has been deserialized");
    server_ctxts.resize(dataNum);
    for(auto& ctxt : server_ctxts){
        DeserializeFromStream(info_fstream, ctxt, SerType::BINARY);
        getTime();
    }
    
    info_fstream.close();
    Print("server: ciphertexts have been deserialized");    
}

// The server saves the result ciphertext to a file and releases memory
void server_serialize_result(){
    for(auto& ctxt : server_ctxts)
        SerializeToStream(result_fstream, ctxt, SerType::BINARY);
    Print("server: results have been serialized");
    result_fstream.seekp(std::ios::beg);
}

// The client recovers the result ciphertext and decrypts it
inline void client_decrypt_data(){
    vector<Ciphertext<DCRTPoly>> client_ctxts(dataNum);
    for(auto& ctxt : client_ctxts)
        DeserializeFromStream(result_fstream, ctxt, SerType::BINARY);
    result_fstream.close();
    //Print("client: result have been deserialized");

    // Save the decrypted result into plaintext and print it
    client_result_ptxts.resize(dataNum);
    for(int i = 0;i < dataNum;i++){
        client_context->Decrypt(client_keyPair.secretKey, client_ctxts[i], &client_result_ptxts[i]);
        client_result_ptxts[i]->SetLength(dataLen);
    }
    Print("client: result have been decrypted");
}

/**
 * @brief Print the calculation results of raw data and homomorphic computation results for 
 *       debugging and result comparison.
 * @param check determines whether to perform differential comparison.
 **/
inline void PrintAndCheckResult(bool check = false){
    isAllCorrect = true;
    // Print("answer:", 1, NO_STAR_LINE);
    // for(int j = 0; j < dataNum; j++){
    //     Printf("data%d: ", j);
    //     for(int i = 0; i < frontLen; i++)
    //         Printf("%ld%c", data[j][i], SPACE_ENDL);
    // }
    // Print("fhe:", 1, NO_STAR_LINE);
    for(int j = 0; j < dataNum; j++){
        vector<dataType> fhe_result;
        if(client_result_ptxts.size() == 0){
            Plaintext ptxt;
            client_context->Decrypt(client_keyPair.secretKey, server_ctxts[j], &ptxt);
            fhe_result = ptxt->GetPackedValue();
        }else
            fhe_result = client_result_ptxts[j]->GetPackedValue();
        if(check){
            bool isCorrect = checkEquality(data[j], fhe_result, ptxt_mod);
            string wrong_result = (string)COUT_RED + "incorrect"  + (string)COUT_END_COLOR;
            if(!isCorrect) {
                Printf("data%d: ", j);
                for(int i = 0; i < frontLen; i++) Printf("%ld%c", data[j][i], SPACE_ENDL);
                Printf("fhe%d: ", j);
                for(int i = 0; i < frontLen; i++) Printf("%ld%c", PTXT_MOD_OFFSET(fhe_result[i]), SPACE_ENDL);
                Print_words({"client: the evaluation result", ToStr(j), "is", wrong_result}, 2);
                isAllCorrect = false;
                ERROR_EXIT("client: the evaluation result is wrong");
            }
        }
    }
}

// Perform synchronized computation using raw data for differential testing.
// dst = v1 + v2
void vector_add(vector<dataType>& v1, vector<dataType>& v2, vector<dataType>& dst){
    int size = v1.size();
    for(int i = 0;i < size;i++)
        dst[i] = NOT_NEG_MOD(v1[i] + v2[i]);
}

// dst = v1 - v2
inline void vector_sub(vector<dataType>& v1, vector<dataType>& v2, vector<dataType>& dst){
    int size = v1.size();
    for(int i = 0;i < size;i++)
        dst[i] = NOT_NEG_MOD(v1[i] - v2[i]);
}

// dst = v1 * v2
inline void vector_mul(vector<dataType>& v1, vector<dataType>& v2, vector<dataType>& dst){
    int size = v1.size();
    for(int i = 0;i < size;i++)
        dst[i] = NOT_NEG_MOD(v1[i] * v2[i]);
}

inline void clear_all_data(){
    dataNum = 0;
    dataLen = 0;
    frontLen = 0;
    maxLevel = 0;
    muldepth = 0;
    msg.clear_param();
    // client_context->ClearEvalMultKeys();
    // client_context->ClearEvalAutomorphismKeys();
    // client_context.reset();
    // server_context->ClearEvalMultKeys();
    // server_context->ClearEvalAutomorphismKeys();
    // server_context.reset();
    server_pk.reset();
    client_keyPair.secretKey.reset();
    client_keyPair.publicKey.reset();
    // CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
    vector<vector<dataType>>().swap(data);
    vector<Ciphertext<DCRTPoly>>().swap(server_ctxts);
    vector<Plaintext>().swap(client_result_ptxts);
}

