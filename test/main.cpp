#include <sodium.h>

#include <array>
#include <bitset>
#include <cassert>
#include <iostream>
#include <memory>
#include <protocol_5_1.hpp>

#include "rand.hpp"
#include "sodium/crypto_core_ristretto255.h"
#include "sodium/crypto_scalarmult_ristretto255.h"
#include "sodium/randombytes.h"

int main(void) {
    if (sodium_init() == -1) {
        return 1;
    }

    const int N = 1000;
    const int L = 160;

    // generate Receiver
    // std::allocator<std::bitset<N>> allocator;
    // std::unique_ptr<std::bitset<N>> o(allocator.allocate(1));
    HeapBits<N> o = std::make_unique<Bits<N>>();
    rand_bitset<N>(o.get());
    HeapBits<N> o_test = std::make_unique<Bits<N>>(*o);

    Receiver<N, L>* rec = new Receiver<N, L>(std::move(o));

    // generate Sender
    HeapArr<Bits<L>[2], N> msgs = std::make_unique<Arr<Bits<L>[2], N>>();
    for (size_t i = 0; i < N; i++) {
        rand_bitset<L>(&(*msgs)[i][0]);
        rand_bitset<L>(&(*msgs)[i][1]);
    }

    HeapArr<Bits<L>[2], N> msgs_test =
        std::make_unique<Arr<Bits<L>[2], N>>(*msgs);

    Sender<N, L>* sen = new Sender<N, L>(std::move(msgs));

    rec->send_key_material(sen);
    sen->send_ciphertexts(rec);
    HeapArr<Bits<L>, N> result = rec->compute();

    for (size_t i = 0; i < N; i++) {
        Bits<L> res = (*result)[i];
        Bits<L> test = (*msgs_test)[i][(*o_test)[i]];
        for (size_t i = 0; i < L; i++) {
            assert(res[i] == test[i]);
        }
    }

    delete rec;
    delete sen;

    // Point kdf_test;
    // crypto_core_ristretto255_random(kdf_test);
    // Bits<N> bits = kdf2<N>(kdf_test);
    // std::cout << bits << std::endl;

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
    for (size_t i = 0; i < 32; i++) {
        assert(gab[i] == gba[i]);
    }

    return 0;
}
