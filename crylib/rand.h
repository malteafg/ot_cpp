#ifndef RAND_H
#define RAND_H

#include <bitset>

const int N = 1000;
const int INT_SIZE = (N + 64 - 1) / 64;
std::bitset<N> rand_bitset();

#endif
