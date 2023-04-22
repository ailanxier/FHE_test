#pragma once

#define PTXT_MOD_OFFSET(num) (num < 0 ? num + ptxt_mod : num)
#include "util_cout.h"
constexpr double EPSILON = 0.001;


/**
 * Function to check equality of 2 numeric vectors
 *
 * @param a              first vector to compare
 * @param b              second vector to compare
 * @param ptxt_mod       plaintext modulus
 * @return               true if a and b are equal, false otherwise
 */
template<typename T>
bool checkEquality(const std::vector<T>& a,
                   const std::vector<T>& b, dataType ptxt_mod) {
    if(a.size() != b.size())
        ERROR_EXIT("Result has invalid length");
    
    // OpenFHE assumes that plaintext is in the range of [-p/2, p/2]
    bool cmp = std::equal(a.begin(), a.end(), b.begin(), [&](const T& x, const T& y) {
        return x == PTXT_MOD_OFFSET(y);
    });
    return cmp;
}