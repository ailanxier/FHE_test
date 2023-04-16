#ifndef OPENFHE_TEST_H
#define OPENFHE_TEST_H

#include "OpenFHE_setting.h"
#include "protobuf_parser.h"
#include "util.h"

const char* info_fileName = "info.txt";
const char* result_filename = "result.txt";
// frontLen is used for debugging
int dataLen, dataNum, frontLen;
bool isStrict = false;

CCParams<CryptoContextCKKSRNS> parameters;
CryptoContext<DCRTPoly> client_context, server_context;
KeyPair<DCRTPoly> client_keyPair;
PublicKey<DCRTPoly> server_pk;
vector<vector<dataType>> data;
vector<Ciphertext<DCRTPoly>> server_ctxts;
vector<Plaintext> client_result_ptxts;
std::fstream info_fstream(info_fileName, std::ios::trunc | std::ios::in | std::ios::out | std::ios::binary);
std::fstream result_fstream(result_filename, std::ios::trunc | std::ios::in | std::ios::out | std::ios::binary);
Root msg;

// Homomorphic context environment configuration for the client
void client_init_context(){
    std::ifstream data_ifile("../../Refine_Protobuf_Mutator/proto_seed/bin/0.txt", std::ios::in);
    if(!data_ifile.is_open()) 
        ERROR_EXIT("client error: fail to open data file");
    msg.ParseFromIstream(&data_ifile);
    // msg.PrintDebugString();
    Print("client: Initialising context object ...");
    Message2FHEParameters(msg, parameters, client_context, client_keyPair);
    isStrict = msg.isstrict();

    // Write the encrypted context, keys except secretKey into a file
    if(!info_fstream.is_open()) 
        ERROR_EXIT("client error: fail to open file to save context");
    SerializeToStream(info_fstream, client_context, SerType::BINARY);
    Print("client: the cryptocontext has been serialized");

    SerializeToStream(info_fstream, client_keyPair.publicKey, SerType::BINARY);
    Print("client: the public key has been serialized");

    // Serialize the relinearization (evaluation) key for homomorphic multiplication
    if (!client_context->SerializeEvalMultKey(info_fstream, SerType::BINARY))
        ERROR_EXIT("client error: fail to write serialization of the eval mult keys");
    Print("client: the eval mult keys have been serialized");

    // Serialize the rotation key for homomorphic rotation
    if (!client_context->SerializeEvalAutomorphismKey(info_fstream, SerType::BINARY))
        ERROR_EXIT("client error: fail to write serialization of the rotation keys");
    Print("client: the rotation keys have been serialized");
}

// Encrypt the original information on the client side and write it into a file
void client_encrypt_data(){
    auto alldataList = msg.evaldata().alldatalists();
    dataLen = client_context->GetEncodingParams()->GetBatchSize();
    dataNum = alldataList.size();
    // postprocess make sure dataNum > 0
    assert(dataNum > 0); 
    frontLen = msg.evaldata().len();
    data.resize(dataNum, vector<dataType>(dataLen));
    for(int i = 0; i < dataNum; i++){
        auto dataList = alldataList[i].datalist();
        int j = 0;
        for(auto num : dataList)
            data[i][j++] = num;
    }
    for(int i = 0; i < dataNum; i++){
        auto client_ptxt = client_context->MakeCKKSPackedPlaintext(data[i]);
        auto client_ctxt = client_context->Encrypt(client_keyPair.publicKey, client_ptxt);
        SerializeToStream(info_fstream, client_ctxt, SerType::BINARY);
    }
    Print("client: ciphertexts have been serialized");
    // Set the file stream back to the beginning of the file.
    info_fstream.seekp(std::ios::beg);
}

// The server recovers the context environment and ciphertext from the file 
void server_init_context(){
    server_ctxts.resize(dataNum);
    DeserializeFromStream(info_fstream, server_context, SerType::BINARY);
    Print("server: the cryptocontext has been deserialized");

    DeserializeFromStream(info_fstream, server_pk, SerType::BINARY);
    Print("server: the public key has been deserialized");

    if (!server_context->DeserializeEvalMultKey(info_fstream, SerType::BINARY)) 
        ERROR_EXIT("Could not deserialize the eval mult key file");
    Print("server: the eval mult keys has been deserialized");

    if (!server_context->DeserializeEvalAutomorphismKey(info_fstream, SerType::BINARY)) 
        ERROR_EXIT("Could not deserialize the rotation keys file");
    Print("server: the rotation keys has been deserialized");

    for(auto& ctxt : server_ctxts)
        DeserializeFromStream(info_fstream, ctxt, SerType::BINARY);
    info_fstream.close();
    Print("server: three ciphertexts have been deserialized");    

    if(!result_fstream.is_open())
        ERROR_EXIT("server error: fail to open file to save ctxt");
}

// The server saves the result ciphertext to a file and releases memory
void server_serialize_result(){
    server_ctxts.resize(dataNum);
    for(auto& ctxt : server_ctxts){
        SerializeToStream(result_fstream, ctxt, SerType::BINARY);
        ctxt.reset();
    }
    Print("server: results have been serialized");
    result_fstream.seekp(std::ios::beg);
    server_pk.reset();
    server_context.reset();
}

// The client recovers the result ciphertext and decrypts it
void client_decrypt_data(){
    vector<Ciphertext<DCRTPoly>> client_ctxts(dataNum);
    for(auto& ctxt : client_ctxts)
        DeserializeFromStream(result_fstream, ctxt, SerType::BINARY);
    result_fstream.close();
    Print("client: result have been deserialized");

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
void PrintAndCheckResult(bool check = false){
    Print("answer:", 1, NO_STAR_LINE);
    for(int j = 0; j < dataNum; j++){
        Printf("data%d: ", j);
        for(int i = 0; i < dataLen; i++)
            Printf("%.13lf%c", data[j][i], SPACE_ENDL);
    }
    Print("fhe:", 1, NO_STAR_LINE);
    for(int j = 0; j < dataNum; j++){
        vector<dataType> fhe_result;
        int64_t lower_bound_precision;
        if(client_result_ptxts.size() == 0){
            Plaintext ptxt;
            client_context->Decrypt(client_keyPair.secretKey, server_ctxts[j], &ptxt);
            fhe_result = ptxt->GetRealPackedValue();
            lower_bound_precision = ptxt->GetLogPrecision();
        }else{
            fhe_result = client_result_ptxts[j]->GetRealPackedValue();
            lower_bound_precision = client_result_ptxts[j]->GetLogPrecision();
        }
        double precision = 1.0 / (1L << lower_bound_precision) * 10;
        printf("lower_bound_precision: %ld precision: %.13lf\n", lower_bound_precision, precision);
        Printf("data%d: ", j);
        for(int i = 0; i < dataLen; i++)
            Printf("%.13lf%c", fhe_result[i], SPACE_ENDL);
        if(check){
            checkEquality(data[j], fhe_result, precision);
            Print_words({"client: the evaluation result", ToStr(j), "is correct."}, 2);
        }
    }
}

// Perform synchronized computation using raw data for differential testing.
// dst = v1 + v2
void vector_add(vector<double>& v1, vector<double>& v2, vector<double>& dst){
    int size = v1.size();
    for(int i = 0;i < size;i++)
        dst[i] = (v1[i] + v2[i]) ;
}

void vector_add(vector<double>& v, const double num, vector<double>& dst){
    int size = v.size();
    for(int i = 0;i < size;i++)
        dst[i] = (v[i] + num) ;
}

// dst = v1 - v2
void vector_sub(vector<double>& v1, vector<double>& v2, vector<double>& dst){
    int size = v1.size();
    for(int i = 0;i < size;i++)
        dst[i] = (v1[i] - v2[i]) ;
}

void vector_sub(vector<double>& v, const double num, vector<double>& dst){
    int size = v.size();
    for(int i = 0;i < size;i++)
        dst[i] = (v[i] - num) ;
}

// dst = v1 * v2
void vector_mul(vector<double>& v1, vector<double>& v2, vector<double>& dst){
    int size = v1.size();
    for(int i = 0;i < size;i++)
        dst[i] = (v1[i] * v2[i]) ;
}

void vector_mul(vector<double>& v1, const double num, vector<double>& dst){
    int size = v1.size();
    for(int i = 0;i < size;i++)
        dst[i] = (v1[i] * num) ;
}

#endif
