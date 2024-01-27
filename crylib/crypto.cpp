#include <algorithm>
#include <cassert>
#include <iostream>
#include <iterator>
#include <sodium.h>
// #include <sodium/crypto_core_ristretto255.h>
// #include <sodium/crypto_scalarmult_ristretto255.h>

using Point = unsigned char[crypto_core_ristretto255_BYTES];
using Scalar = unsigned char[crypto_core_ristretto255_SCALARBYTES];

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
