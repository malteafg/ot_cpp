#include "sodium/randombytes.h"
#include <bitset>
#include <cstdint>
#include <sodium.h>

using std::bitset;

template <int N> std::bitset<N> rand_bitset() {
  const int INT_SIZE = (N + 64 - 1) / 64;
  std::uint64_t r_bytes[INT_SIZE];
  randombytes_buf(r_bytes, sizeof r_bytes);

  bitset<N> o;
  std::uint64_t *bitset_pointer = reinterpret_cast<std::uint64_t *>(&o);

  for (int i = 0; i < INT_SIZE; i++) {
    bitset_pointer[i] = r_bytes[i];
  }

  return o;
}
