#include <algorithm>
#include <array>
#include <bitset>
#include <cassert>
#include <cstdint>
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
  HeapArr<Scalar, N> a;
  HeapBits<N> o;

  // should be optional
  Point u;
  optional<HeapArr<bitset<L>[2], N>> v;

  Receiver(HeapBits<N> o) : o(o), a(std::make_unique<array<Scalar, N>>()) {
    for (int i = 0; i < N; i++) {
      crypto_core_ristretto255_scalar_random(a[i]);
    }

    v = std::nullopt;
  }
};

int dh() {
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

  assert(std::ranges::equal(gab, gba));
  for (int i = 0; i < 32; i++) {
    assert(gab[i] == gba[i]);
  }

  return 0;
}
