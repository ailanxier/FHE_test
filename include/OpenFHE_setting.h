#ifndef OPENFHE_SETTING_H
#define OPENFHE_SETTING_H

#include <openfhe.h>
#include <cryptocontext-ser.h>
#include <key/key-ser.h>
#include <scheme/bgvrns/bgvrns-ser.h>
#include <ciphertext-ser.h>

#define RECV_BUF_MAXSIZE 10000000 
#define SEND_BUF_MAXSIZE 10000000

// 保存 OpenFHE 上下文和密文的文件名
const char* client_send_fileName = "openfhe_client_send";
const char* server_recv_fileName = "openfhe_server_recv";
const char* client_result_filename = "openfhe_client_result";
const char* server_result_filename = "openfhe_server_result";

// const char* client_pk_fileName = "openfhe_client_pk";
// const char* server_pk_fileName = "openfhe_server_pk";

// const char* client_ek_fileName = "openfhe_client_ek";
// const char* server_ek_fileName = "openfhe_server_ek";

// const char* client_c1_fileName = "openfhe_client_c1";
// const char* server_c1_fileName = "openfhe_server_c1";
// const char* client_c2_fileName = "openfhe_client_c2";
// const char* server_c2_fileName = "openfhe_server_c2";
// const char* client_c3_fileName = "openfhe_client_c3";
// const char* server_c3_fileName = "openfhe_server_c3";

// const char* client_result2_filename = "openfhe_client_result2";
// const char* server_result2_filename = "openfhe_server_result2";

#endif