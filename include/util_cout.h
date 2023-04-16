#ifndef UTIL_COUT_H
#define UTIL_COUT_H

#include <iostream>
#include <string>
#include <iomanip>
#include <stdarg.h>
#include "general_setting.h"
#include "util_string.h"

#define COUT_RED "\033[31m"
#define COUT_GREEN "\033[32m"
#define COUT_END_COLOR "\033[0m"
#define __output(...) \
    printf(__VA_ARGS__);
 
#define __format(__fmt__) "%s(%d)-<%s>: " __fmt__ "\n"

/**
 * @brief Print the file name, line number and function where the error occurred.
 **/
#define TRACE_FILE_LINE_FUNCTION(__fmt__, ...) \
    __output(__format(__fmt__), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__);

/**
 * @brief Locate the position of the error and print the error message. 
 *        Let AFL detect crash caused by differential testing.
 * @param error_message some hints of the error
 **/
#define ERROR_EXIT(error_message)\
    do{\
        TRACE_FILE_LINE_FUNCTION("error occurred.");\
        perror(error_message);\
        abort();\
        exit(AFL_CRASH_CODE);\
    }while(0)

/**
 * @brief Handle exceptions captured by the library, exit normally without counting as a crash.
 * @param throw_message some hints of the exception
 **/
#define THROW_EXCEPTION(throw_message)\
    do{\
        TRACE_FILE_LINE_FUNCTION("fhe throw exception.");\
        printf("throw message: %s\n", throw_message);\
        exit(0);\
    }while(0)

/**
 * @brief print one line of '*' with a line feed.
 * @param star_num number of stars (default is 50)
 **/
inline void print_one_star_line(int star_num = 50){
    #ifdef DEBUG
        cout << std::setw(star_num) << std::setfill('*') << "\n";
    #endif
}

/**
 * @brief Print one line of  strings with newline
 * @param words         indefinite lists of string
 * @param highlight_pos Not highlighted by default (= 0). 
 *      A value greater than zero indicates where the word is to be highlighted (1-indexed).
 * @param segment_flag  print one line of '*' after this line by default (= true).
 *      A `bool` to determine whether to print '*'.
 **/
inline void Print_words(const vector<string>& words, int highlight_pos = 0, bool segment_flag = true){
    #ifdef DEBUG
        if(highlight_pos > (int)words.size()){
            cout << COUT_RED << "cout warning: highlight_pos is out of bounds" 
                << COUT_END_COLOR << endl;
            highlight_pos = 0;
        }
        int i = 1;
        for(const auto& word : words){
            if(i == highlight_pos)
                cout << COUT_GREEN << word << COUT_END_COLOR << " ";
            else 
                cout << word << " ";
            i++;
        }
        cout << endl;
        if(segment_flag)
            print_one_star_line();
    #endif
}

/**
 * @brief a simple wrapper for "print_words()" when just printing one string
 * @param word one string
 * @param highlight_pos the string will be highlighted by default (= 1), otherwise 
 *      otherwise it will not be highlighted (= 0).
 * @param segment_flag print one line of '*' after this line by default (= true).
 *      A `bool` to determine whether to print '*'.
 **/
inline void Print(string word, int highlight_pos = 1, bool segment_flag = true){
    Print_words({word}, highlight_pos, segment_flag);
}

/**
 * @brief a simple wrapper for "print_words()" when just printing one number
 * @param number arithmetic number
 * @param highlight_pos the string will be highlighted by default (= 1), otherwise 
 *      otherwise it will not be highlighted (= 0).
 * @param segment_flag print one line of '*' after this line by default (= true).
 *      A `bool` to determine whether to print '*'.
 **/
template<typename T>
inline typename std::enable_if<std::is_arithmetic_v<T>, void>::type print(T number, int highlight_pos = 1, bool segment_flag = true){
    Print_words({ToStr(number)}, highlight_pos, segment_flag);
}

/**
 * @brief A simple wrapper for the printf() function that only prints information in DEBUG mode.
 **/
inline void Printf(const char* fmt, ...){
    #ifdef DEBUG
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    #endif
}

#endif