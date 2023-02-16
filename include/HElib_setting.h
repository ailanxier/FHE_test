#ifndef HELIB_SETTING_H
#define HELIB_SETTING_H

#include <helib/FHE.h>

#define RECV_BUF_MAXSIZE 10000000 
#define SEND_BUF_MAXSIZE 10000000

// 保存 HElib 上下文和密文的文件名
const char* info_fileName = "info.txt";
const char* result_filename = "result.txt";
// const char* server_recv_fileName = "helib_server_recv.txt";
// const char* server_result_filename = "helib_server_result.txt";

#endif