#ifndef UTIL_COUT_H
#define UTIL_COUT_H

#include <iostream>
#include <string>
#include <general_setting.h>

#define SOUT std::cout
#define ENDL std::endl
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
 * @param error_message some hints of the error
 **/
#define ERR_EXIT(error_message)\
    do{\
        TRACE_FILE_LINE_FUNCTION("error occurred.");\
        perror(error_message);\
        exit(EXIT_FAILURE);\
    }while(0)

/**
 * @brief print one line of '*' with a line feed.
 **/
void print_one_star_line(){
    SOUT << "*********************************" << ENDL;
}

/**
 * @brief Print one line of  strings with newline
 * @param words indefinite lists of string
 * @param highlight_pos Not highlighted by default (= 0). 
 *      A value greater than zero indicates where the word is to be highlighted (1-indexed).
 * @param segment_flag print one line of '*' after this line by default (= true).
 *      A `bool` to determine whether to print '*'.
 **/
void print_words(std::initializer_list<std::string> words, int highlight_pos = 0, bool segment_flag = true){
    if(highlight_pos > words.size()){
        SOUT << COUT_RED << "cout warning: highlight_pos is out of bounds" 
             << COUT_END_COLOR << ENDL;
        highlight_pos = 0;
    }
    int i = 1;
    for(const auto& word : words){
        if(i == highlight_pos)
            SOUT << COUT_GREEN << word << COUT_END_COLOR << " ";
        else 
            SOUT << word << " ";
        i++;
    }
    SOUT << ENDL;
    if(segment_flag)
        print_one_star_line();
}

#endif