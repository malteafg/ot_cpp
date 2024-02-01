#include "crypto.h"
#include "rand.h"
#include "sodium/randombytes.h"
#include <algorithm>
#include <array>
#include <bitset>
#include <cassert>
#include <iostream>
#include <memory>
#include <optional>
#include <sodium.h>

using Point = unsigned char[crypto_core_ristretto255_BYTES];
using Scalar = unsigned char[crypto_core_ristretto255_SCALARBYTES];

using std::array;
using std::bitset;
using std::optional;

template <typename T, int N> using HeapArr = std::unique_ptr<std::array<T, N>>;
template <int N> using HeapBits = std::unique_ptr<std::bitset<N>>;

template <int N, int L> class Sender {
  HeapArr<bitset<L>[2], N> x;
  optional<HeapArr<Point[2], N>> h;

  Sender(HeapArr<bitset<L>[2], N> x) : x(x) { h = std::nullopt; }
};

template <int N, int L> class Receiver {
  HeapBits<N> o;
  HeapArr<Scalar, N> a;

  // should be optional
  Point u;
  optional<HeapArr<bitset<L>[2], N>> v;

public:
  Receiver(HeapBits<N> o)
      : o(std::move(o)), a(std::make_unique<array<Scalar, N>>()) {
    for (int i = 0; i < N; i++) {
      crypto_core_ristretto255_scalar_random((*a)[i]);
    }
    std::cout << "Bitset: " << *(this->o) << std::endl;
    v = std::nullopt;
  }
};

int dh() {
  const int N = 32;
  const int L = 16;

  // generate Receiver
  std::allocator<bitset<N>> allocator;
  std::unique_ptr<bitset<N>> o(allocator.allocate(1));
  rand_bitset<N>(o.get());

  Receiver<N, 50> rec(std::move(o));

  // generate Sender
  HeapArr<bitset<L>[2], N> msgs = std::make_unique<array<bitset<L>[2], N>>();
  // for (int i = 0; i < N; i++) {
  //   std::cout << "msgs: " << (*msgs)[i][0] << std::endl;
  //   std::cout << "msgs: " << (*msgs)[i][1] << std::endl;
  // }

  for (int i = 0; i < N; i++) {
    rand_bitset<L>(&(*msgs)[i][0]);
    rand_bitset<L>(&(*msgs)[i][1]);
    // (*msgs)[i][0] = rand_bitset<L>();
    // (*msgs)[i][1] = rand_bitset<L>();
  }

  // for (int i = 0; i < N; i++) {
  //   std::cout << "after: " << (*msgs)[i][0] << std::endl;
  //   std::cout << "after: " << (*msgs)[i][1] << std::endl;
  // }

  unsigned char x[crypto_core_ristretto255_HASHBYTES];
  randombytes_buf(x, sizeof x);

  unsigned char px[crypto_core_ristretto255_BYTES];
  crypto_core_ristretto255_from_hash(px, x);

  Scalar a, b;
  Point ga, gb, gab, gba;

  crypto_core_ristretto255_scalar_random(a);
  crypto_core_ristretto255_scalar_random(b);

  crypto_scalarmult_ristretto255_base(ga, a);
  crypto_scalarmult_ristretto255_base(gb, b);

  crypto_scalarmult_ristretto255(gab, b, ga);
  crypto_scalarmult_ristretto255(gba, a, gb);

  std::cout << "hello\n";

  // assert(std::ranges::equal(gab, gba));
  for (int i = 0; i < 32; i++) {
    assert(gab[i] == gba[i]);
  }

  return 0;
}
