extern "C" {
    #include "she.h"
    #include "bit_array.h"
}


#include <cassert>
#include <random>
#include <memory>
#include <string>
#include <sstream>

#include <gmpxx.h>

using namespace std;


// =====
// UTILS
// =====

shared_ptr<gmp_randclass> make_random_generator() {
    random_device dev("/dev/urandom");
    shared_ptr<gmp_randclass> gen(new gmp_randclass(gmp_randinit_default));
    gen->seed(dev());
    return gen;
}

// Return random GMP integer in range from `a` to `b` inclusive
mpz_class _random_mpz(const mpz_class& a, const mpz_class& b) {
    auto gen = make_random_generator();
    return a + gen->get_z_range(b-a+1);
}

// Return random odd GMP integer in range from `a` to `b` inclusive
mpz_class _random_odd_mpz(const mpz_class& a, const mpz_class& b) {
    mpz_class res;
    while ((res = _random_mpz(a, b)) % 2 == 0) {};
    return res;
}

// Return random GMP integer having `n` bits
mpz_class _random_mpz_bits(unsigned int n) {
    auto gen = make_random_generator();
    return gen->get_z_bits(n);
}

// Return random odd GMP integer having `n` bits
mpz_class _random_odd_mpz_bits(unsigned int n) {
    mpz_class res;
    while ((res = _random_mpz_bits(n)) % 2 == 0) {};
    return res;
}

// ======
// KEYGEN
// ======

struct she_private_key_t {
    shared_ptr<mpz_class> p;
    unsigned int etha; // bit length of private key p
    unsigned int s;
    unsigned int l;
};

void
she_free_private_key(she_private_key_t* sk) {
    if (sk) {
        delete sk;
    }
    sk = 0;
}

struct she_public_key_t {
    shared_ptr<mpz_class> x;
    unsigned int gamma; // bit length of public key x
    unsigned int s;
    unsigned int l;
};

void
she_free_public_key(she_public_key_t* pk) {
    if (pk) {
        delete pk;
    }
    pk = 0;
}

// Generate private key
//   s: security parameter
//   l: supported ciphertext length in bits, equivalent to (log m) rounded up,
//      where m is the number of blocks in the database
she_private_key_t*
she_generate_private_key(unsigned int s, unsigned int l)
{
    if (s == 0 || l == 0) {
        return nullptr;
    }

    unsigned int etha = (s+3) * l;

    // Chooses a random odd etha-bit integer p from (2Z + 1)
    // intersection (2^(etha-1), 2^etha) as the secret key sk.

    auto p = _random_odd_mpz_bits(etha);

    // p is the secret key
    auto sk = new she_private_key_t();
    sk->p = shared_ptr<mpz_class>(new mpz_class(p));
    sk->etha = etha;
    sk->l = l;
    sk->s = s;

    return sk;
}


// Generate public key
//   sk: generated private key
she_public_key_t*
she_generate_public_key(she_private_key_t* sk)
{
    if (!sk) {
        return nullptr;
    }

    auto s = sk->s;
    auto l = sk->l;
    unsigned int gamma = (5 * (s+3) * l / 2);

    auto p = sk->p;

    // Chooses random odd q0 from (2Z + 1) intersection [1, 2^gamma/p)
    // and sets pk = q0 * p.
    mpz_class upper_bound;
    mpz_ui_pow_ui(upper_bound.get_mpz_t(), 2, gamma);
    mpz_cdiv_q(upper_bound.get_mpz_t(), upper_bound.get_mpz_t(), p->get_mpz_t());
    mpz_class q0 = _random_odd_mpz(1, upper_bound-1);
    mpz_class x = q0 * (*p);

    // x is the public key
    auto pk = new she_public_key_t();
    pk->x = shared_ptr<mpz_class>(new mpz_class(x));
    pk->s = s;
    pk->l = l;
    pk->gamma = gamma;

    return pk;
}

// ==========
// ENCRYPTION
// ==========

struct she_ciphertext_t {
    vector<mpz_class> data;
};

void
she_free_ciphertext(she_ciphertext_t* c) {
    if (c) {
        delete c;
    }
    c = 0;
}


// Encrypt array of bits
//   pk: public key
//   sk: private key
//   m: array of bits
//   n: array size
she_ciphertext_t*
she_encrypt(she_public_key_t* pk, she_private_key_t* sk, BIT_ARRAY* m)
{
    if (!m || !pk || !sk || pk->l != sk->l || pk->s != sk->s) {
        return nullptr;
    }

    auto x = pk->x;
    auto p = sk->p;

    auto s = sk->s;

    auto gamma = pk->gamma;
    auto res = new she_ciphertext_t();

    auto n = bit_array_length(m);

    for (int i=0; i<n; ++i) {

        // Chooses random q from [1, 2^gamma/p)
        mpz_class upper_bound;
        mpz_ui_pow_ui(upper_bound.get_mpz_t(), 2, gamma);
        mpz_cdiv_q(upper_bound.get_mpz_t(), upper_bound.get_mpz_t(), p->get_mpz_t());
        auto q = _random_mpz(1, upper_bound-1);

        // Chooses random noise r from [1, 2^s)
        mpz_class bound;
        mpz_ui_pow_ui(bound.get_mpz_t(), 2, s);
        auto r = _random_mpz(1, bound-1);

        // Encrypts m[i]
        res->data.push_back((q * (*p) + 2*r + bit_array_get_bit(m, i)) % (*x));
    }

    return res;
}

// Decrypt array of bits
//   sk: private key
//   c: ciphertext
BIT_ARRAY*
she_decrypt(she_private_key_t* sk, she_ciphertext_t* c)
{
    if (!sk || !c) {
        return nullptr;
    }

    auto p = sk->p;

    unsigned int n = c->data.size();

    auto res = bit_array_create(n);

    for (int i=0; i<n; ++i) {
        // Decrypts c[i]
        mpz_class t = c->data[i] % (*p) % 2;
        bit_array_assign_bit(res, i, t.get_si());
    }

    return res;
}

// ==========
// OPERATIONS
// ==========

// XOR ciphertexts `cs`
//   sk: private key
//   a: array of ciphertexts
//   n: number of ciphertexts
//   m: size of ciphertexts
she_ciphertext_t *
she_xor(she_public_key_t* pk, she_ciphertext_t* cs,
    unsigned int n, unsigned m)
{
    if (!pk || !cs || n == 0 || m == 0) {
        return nullptr;
    }

    for (int i=0; i<n; ++i) {
        if (cs[i].data.size() != m) {
            return nullptr;
        }
     }

    auto x = pk->x;

    auto res = new she_ciphertext_t();
    for (int j=0; j<m; ++j) {
        mpz_class acc = 0;
        for (int i=0; i<n; ++i) {
            acc += cs[i].data[j];

            // TODO: Optimize this. 5 was picked randomly in order for
            // mod division to not be performed every time, since division is
            // expensive...
            // ...but so is operations on larger numbers
            // Should depend on security parameter
            if (i % 5 == 0) {
                acc %= (*x);
            }
        }
        res->data.push_back(acc);
    }

    return res;
}

// Compute AND product of the sum of ciphertext `a` and each
// negated plaintext row in `b`
//   pk: public key
//   b: bit matrix flattened to bit array
//   n: number of rows
//   l: number of columns
she_ciphertext_t*
she_sumprod(she_public_key_t* pk, she_ciphertext_t* a, BIT_ARRAY* b,
    unsigned int n, unsigned int l)
{
    if (!pk || !a || !b || n == 0 || l == 0 ||
        a->data.size() < l || bit_array_length(b) != n*l)
    {
        return nullptr;
    }

    auto x = pk->x;

    auto res = new she_ciphertext_t();

    for (int i=0; i<n; ++i) {
        mpz_class acc = 1;
        for (int j=0; j<l; ++j) {
            auto beta = bit_array_get_bit(b, i*l + j);
            acc *= (a->data[j] + beta + 1);

            // TODO: Optimize this. 3 was picked randomly in order for
            // mod division to not be performed every time, since division is
            // expensive...
            // ...but so is operations on larger numbers
            // Should depend on security parameter
            if (i % 3 == 0) {
                acc %= (*x);
            }
        }
        acc %= (*x);
        (res->data).push_back(acc);
    }

    return res;
}

// Compute dot product of `g` and each column of `b` matrix
//   pk: public key
//   g: ciphertext
//   b: flattened to bit array bit matrix
//   n: number of rows
//   m: number of columns
she_ciphertext_t*
she_dot(she_public_key_t* pk, she_ciphertext_t* g, BIT_ARRAY* b,
    unsigned int n, unsigned int m)
{
    if (!pk || !g || !b || n == 0 || m == 0 ||
        g->data.size() < n || bit_array_length(b) != n*m)
    {
        return nullptr;
    }

    auto x = pk->x;

    auto res = new she_ciphertext_t();

    for (int j=0; j<m; ++j) {
        mpz_class acc = 0;
        int c = 0;
        for (int i=0; i<n; ++i) {
            auto bit = bit_array_get_bit(b, i*m + j);
            if (bit) {
                acc += g->data[i];
                ++c;
                // TODO: Optimize this. 5 was picked randomly in order for
                // mod division to not be performed every time, since division is
                // expensive...
                // ...but so is operations on larger numbers
                // Should depend on security parameter
                if (c % 5 == 0) {
                    acc %= (*x);
                }
            }
        }
        acc %= (*x);
        res->data.push_back(acc);
    }

    return res;
}

// =============
// SERIALIZATION
// =============

char*
she_serialize_private_key(she_private_key_t *sk) {
    if (!sk) {
        return nullptr;
    }

    stringstream ss;
    ss << sk->p->get_str(62) << '/'
       << mpz_class(sk->etha).get_str(62) << '/'
       << mpz_class(sk->s).get_str(62) << '/'
       << mpz_class(sk->l).get_str(62);
    auto t = ss.str();
    char* res = new char[t.size() + 1];
    strcpy(res, t.c_str());

    return res;
}

// she_private_key_t*
// she_deserialize_private_key(char* s) {
//     if (!s) {
//         return nullptr;
//     }
//
//     istringstream ss(s);
//     string ;
//
//     while (getline()) {
//
//     }
//     return res;
// }

char*
she_serialize_public_key(she_public_key_t *pk) {
    if (!pk) {
        return nullptr;
    }

    stringstream ss;
    ss << pk->x->get_str(62) << '/'
       << mpz_class(pk->gamma).get_str(62) << '/'
       << mpz_class(pk->s).get_str(62) << '/'
       << mpz_class(pk->l).get_str(62);
    auto t = ss.str();
    char* res = new char[t.size() + 1];
    strcpy(res, t.c_str());

    return res;
}

char*
she_serialize_ciphertext(she_ciphertext_t *c) {
    if (!c) {
        return nullptr;
    }

    stringstream ss;
    for (int i=0; i < (c->data.size()); ++i) {
        ss << c->data[i].get_str(62) << '/';
    }
    auto t = ss.str();
    char* res = new char[t.size() + 1];
    strcpy(res, t.c_str());

    return res;
}
