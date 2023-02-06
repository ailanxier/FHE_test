#ifndef HELIB_SETTING_H
#define HELIB_SETTING_H

#include <helib/FHE.h>

#define HElib_RECV_BUF_MAXSIZE 10000000 
#define HElib_RECV_BUF_MINSIZE 10000
#define HElib_SEND_BUF_MAXSIZE 10000000

// 保存 HElib 上下文和密文的文件名
const char* helib_client_context_fileName = "helib_client_context.txt";
const char* helib_server_context_fileName = "helib_server_context.txt";
const char* helib_client_result_filename = "helib_client_result.txt";
const char* helib_server_result_filename = "helib_server_result.txt";

#endif