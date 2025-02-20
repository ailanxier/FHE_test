#ifndef UTIL_CHECK_H
#define UTIL_CHECK_H

#include "util_cout.h"
constexpr double EPSILON = 0.001;

// OpenFHE assumes that plaintext is in the range of [-p/2, p/2]
// #define PTXT_MOD_OFFSET(num) (num < 0 ? num + ptxt_mod : num)

/**
 * Function to check equality of 2 numeric vectors
 *
 * @param a              first vector to compare
 * @param b              second vector to compare
 * @param eps            minimum precision to consider a and b equal. Default is EPSILON
 * @param canTolerant    whether to tolerate the error(when maxLevel = muldepth). Default is false
 * @return               true if a and b are equal, false otherwise
 */
template<typename T>
bool checkEquality(const std::vector<T>& a,
                   const std::vector<T>& b,
                   double eps = EPSILON, bool canTolerant = false) {
    if(a.size() != b.size())
        ERROR_EXIT("Result has invalid length");
    // OpenFHE can't provide exact precision, So use default value
    eps = EPSILON;
    // return abs(a - PTXT_MOD_OFFSET(b)) <= eps; 
    bool cmp = std::equal(a.begin(), a.end(), b.begin(), [&eps](const T& a, const T& b) {
        return fabs(a - b) <= eps; 
    });
    return cmp;
}

#endif