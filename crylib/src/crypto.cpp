// #include "crypto.h"
#include <sodium.h>
#include <algorithm>
#include <array>
#include <bitset>
#include <cassert>
#include <iostream>
#include <memory>
#include <optional>
#include "rand.h"
#include "sodium/crypto_core_ristretto255.h"
#include "sodium/crypto_kdf_hkdf_sha256.h"
#include "sodium/crypto_scalarmult_ristretto255.h"
#include "sodium/randombytes.h"

using Point = unsigned char[crypto_core_ristretto255_BYTES];
using Scalar = unsigned char[crypto_core_ristretto255_SCALARBYTES];

template <typename T, size_t N>
using Arr = std::array<T, N>;
template <typename T, size_t N>
using HeapArr = std::unique_ptr<Arr<T, N>>;

template <size_t N>
using Bits = std::bitset<N>;
template <size_t N>
using HeapBits = std::unique_ptr<Bits<N>>;

void kdf(unsigned char* out, size_t out_len, const unsigned char* ikm,
         size_t ikm_len) {
    unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    crypto_kdf_hkdf_sha256_extract(prk, nullptr, 0, ikm, ikm_len);
    crypto_kdf_hkdf_sha256_expand(out, out_len, nullptr, 0, prk);
}

template <size_t N>
Bits<N> kdf2(Point p) {
    const size_t out_len = N / 8 + 1;
    unsigned char out[out_len];
    kdf(out, out_len, p, crypto_core_ristretto255_BYTES);
    std::bitset<N>& result = *reinterpret_cast<std::bitset<N>*>(out);
    return result;
}

// Forward declaration because of template
template <size_t N, size_t L>
class Receiver;

template <size_t N, size_t L>
class Sender {
    HeapArr<Bits<L>[2], N> x;
    std::optional<HeapArr<Point[2], N>> h;

   public:
    Sender(HeapArr<Bits<L>[2], N> x) : x(std::move(x)) { h = std::nullopt; }

   public:
    void receive_key_material(HeapArr<Point[2], N> h) {
        this->h = std::move(h);
    }

   public:
    void send_ciphertexts(Receiver<N, L>* other) {
        HeapArr<Point[2], N> h;
        if (this->h.has_value()) {
            h = std::move(*this->h);
        } else {
            // std::unreachable() will be a thing in cpp23
            throw std::logic_error("This code is unreachable");
        }

        Scalar r;
        Point u;

        crypto_core_ristretto255_scalar_random(r);
        crypto_scalarmult_ristretto255_base(u, r);

        HeapArr<Bits<L>[2], N> v = std::make_unique<Arr<Bits<L>[2], N>>();
        for (int i = 0; i < N; i++) {
            Point k_0, k_1;
            crypto_scalarmult_ristretto255(k_0, r, (*h)[i][0]);
            crypto_scalarmult_ristretto255(k_1, r, (*h)[i][1]);

            (*v)[i][0] = kdf2<L>(k_0) ^ (*this->x)[i][0];
            (*v)[i][1] = kdf2<L>(k_1) ^ (*this->x)[i][1];
        }

        other->receive_ciphertexts(u, std::move(v));
    }
};

template <size_t N, size_t L>
class Receiver {
    HeapBits<N> o;
    HeapArr<Scalar, N> a;

    // should be optional
    Point u;
    std::optional<HeapArr<Bits<L>[2], N>> v;

   public:
    Receiver(HeapBits<N> o)
        : o(std::move(o)), a(std::make_unique<Arr<Scalar, N>>()) {
        for (int i = 0; i < N; i++) {
            crypto_core_ristretto255_scalar_random((*a)[i]);
        }
        v = std::nullopt;
    }

   public:
    void send_key_material(Sender<N, L>* other) {
        HeapArr<Point[2], N> h = std::make_unique<Arr<Point[2], N>>();
        for (int i = 0; i < N; i++) {
            Point h_i, ga_i;
            crypto_core_ristretto255_random(h_i);
            crypto_scalarmult_ristretto255_base(ga_i, (*this->a)[i]);

            if ((*this->o)[i]) {
                memcpy((*h)[i][0], h_i, sizeof h_i);
                memcpy((*h)[i][1], ga_i, sizeof ga_i);
            } else {
                memcpy((*h)[i][0], ga_i, sizeof ga_i);
                memcpy((*h)[i][1], h_i, sizeof h_i);
            }
        }

        other->receive_key_material(std::move(h));
    }

   public:
    void receive_ciphertexts(Point u, HeapArr<Bits<L>[2], N> v) {
        memcpy(this->u, u, sizeof(Point));
        this->v = std::move(v);
    }

   public:
    HeapArr<Bits<L>, N> compute() {
        HeapArr<Bits<L>[2], N> v;
        if (this->v.has_value()) {
            v = std::move(*this->v);
        } else {
            // std::unreachable() will be a thing in cpp23
            throw std::logic_error("This code is unreachable");
        }

        HeapArr<Point, N> k = std::make_unique<Arr<Point, N>>();
        for (int i = 0; i < N; i++) {
            crypto_scalarmult_ristretto255((*k)[i], (*this->a)[i], this->u);
        }

        HeapArr<Bits<L>, N> x = std::make_unique<Arr<Bits<L>, N>>();
        for (int i = 0; i < N; i++) {
            (*x)[i] = kdf2<L>((*k)[i]) ^ (*v)[i][(*this->o)[i]];
        }

        return x;
    }
};

int dh() {
    const int N = 100000;
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
    for (int i = 0; i < N; i++) {
        rand_bitset<L>(&(*msgs)[i][0]);
        rand_bitset<L>(&(*msgs)[i][1]);
    }

    HeapArr<Bits<L>[2], N> msgs_test =
        std::make_unique<Arr<Bits<L>[2], N>>(*msgs);

    Sender<N, L>* sen = new Sender<N, L>(std::move(msgs));

    rec->send_key_material(sen);
    sen->send_ciphertexts(rec);
    HeapArr<Bits<L>, N> result = rec->compute();

    for (int i = 0; i < N; i++) {
        Bits<L> res = (*result)[i];
        Bits<L> test = (*msgs_test)[i][(*o_test)[i]];
        for (int i = 0; i < L; i++) {
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
    for (int i = 0; i < 32; i++) {
        assert(gab[i] == gba[i]);
    }

    return 0;
}
