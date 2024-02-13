#pragma once

#include <sodium.h>

#include <bitset>
#include <cstring>

#include "sodium/randombytes.h"

// template <size_t N> std::bitset<N> rand_bitset() {
//   const int INT_SIZE = (N + 64 - 1) / 64;
//   std::uint64_t r_bytes[INT_SIZE];
//   randombytes_buf(r_bytes, sizeof r_bytes);

//   std::bitset<N> o;
//   std::uint64_t *bitset_pointer = reinterpret_cast<std::uint64_t *>(&o);

//   for (int i = 0; i < INT_SIZE; i++) {
//     bitset_pointer[i] = r_bytes[i];
//   }

//   return o;
// }

// template <size_t N> void rand_bitset(std::bitset<N> *bitset_ptr) {
//   const int INT_SIZE = (N + 64 - 1) / 64;
//   std::uint64_t r_bytes[INT_SIZE];
//   randombytes_buf(r_bytes, sizeof r_bytes);

//   std::uint64_t *bitset_pointer = reinterpret_cast<std::uint64_t
//   *>(bitset_ptr);

//   for (int i = 0; i < INT_SIZE; i++) {
//     bitset_pointer[i] = r_bytes[i];
//   }
// }

template<size_t N>
void rand_bitset(std::bitset<N>* bitset_ptr) {
    // maybe do it in chunks if stack overflow becomes a problem
    unsigned char randomBytes[N / 8 + 1];
    randombytes_buf(randomBytes, sizeof(randomBytes));
    memcpy(bitset_ptr, randomBytes, sizeof(randomBytes));
}

// template <size_t N> void rand_bitset(std::bitset<N> *bitset_ptr) {
//   const int INT_SIZE = (N + 64 - 1) / 64;
//   std::cout << "hello1\n";
//   std::uint64_t *raw_ptr = reinterpret_cast<std::uint64_t *>(bitset_ptr);
//   std::cout << "hello2\n";
//   randombytes_buf(raw_ptr, INT_SIZE / 8);
//   std::cout << "hello3\n";
// }
