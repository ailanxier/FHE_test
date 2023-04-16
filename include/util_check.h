#ifndef UTIL_CHECK_H
#define UTIL_CHECK_H

#include "util_cout.h"
constexpr double EPSILON = 0.0001;

// OpenFHE assumes that plaintext is in the range of [-p/2, p/2]
// #define PTXT_MOD_OFFSET(num) (num < 0 ? num + ptxt_mod : num)

/**
 * Function to check equality of 2 numeric vectors
 *
 * @param a      first vector to compare
 * @param b      second vector to compare
 * @param eps    minimum precision to consider a and b equal. Default is EPSILON
 */
template<typename T>
void checkEquality(const std::vector<T>& a,
                   const std::vector<T>& b,
                   const double eps = EPSILON) {
    if(a.size() != b.size())
        ERROR_EXIT("Result has invalid length");

    bool cmp = std::equal(a.begin(), a.end(), b.begin(), [&eps](const T& a, const T& b) {
        // return abs(a - PTXT_MOD_OFFSET(b)) <= eps; 
        return abs(a - b) <= eps; 
    });
    if(!cmp) 
        ERROR_EXIT("Result is wrong.");
}

#endif