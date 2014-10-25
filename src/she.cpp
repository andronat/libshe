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

mpz_class _random_mpz(const mpz_class& a, const mpz_class& b) {
    gmp_randclass random_generator(gmp_randinit_default);
    random_device dev("/dev/urandom");
    random_generator.seed(dev());
    return a + random_generator.get_z_range(b);
}

mpz_class _random_odd_mpz(const mpz_class& a, const mpz_class& b) {
    auto res = _random_mpz(a, b);
    // TODO: is this trick harmless in crypto setting?
    if (res % 2 == 0) {
        if (res == a) {
            ++res;
        } else {
            --res;
        }
    }
    return res;
}

// The following should be exposed as C API

// ======
// KEYGEN
// ======

struct she_private_key_t {
    shared_ptr<mpz_class> p;
    unsigned int etha; // bit length of p
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
    unsigned int gamma; // bit length of x
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

she_private_key_t*
she_generate_private_key(unsigned int s, unsigned int l)
{
    // Generate private key
    //   s: security
    //   l: ciphertext length (bits)

    if (s == 0 || l == 0) {
        return nullptr;
    }

    unsigned int etha = (s+3) * l;

    mpz_t scratch;
    mpz_init(scratch);

    // Chooses a random odd etha-bit integer p from (2Z + 1)
    // intersection (2^(etha-1), 2^etha) as the secret key sk.

    mpz_ui_pow_ui(scratch, 2, etha-1);
    mpz_class range(scratch);
    mpz_class p = _random_odd_mpz(mpz_class(range-1), mpz_class(range+1));

    mpz_clear(scratch);

    // p is the secret key
    auto sk = new she_private_key_t();
    sk->p = shared_ptr<mpz_class>(new mpz_class(p));
    sk->etha = etha;
    sk->l = l;
    sk->s = s;

    return sk;
}

she_public_key_t*
she_generate_public_key(she_private_key_t* sk)
{
    // Generate public key
    //   sk: generated private key

    if (!sk) {
        return nullptr;
    }

    auto s = sk->s;
    auto l = sk->l;
    unsigned int gamma = (5 * (s+3) * l / 2);

    auto p = *(sk->p);

    mpz_t scratch;
    mpz_init(scratch);

    // Chooses random odd q0 from (2Z + 1) intersection [1, 2^gamma/p)
    // and sets pk = q0 * p.
    mpz_init(scratch);
    mpz_ui_pow_ui(scratch, 2, gamma);
    mpz_class t(mpz_class(scratch) / p);

    mpz_class q0 = _random_odd_mpz(1, t-1);
    mpz_class x = q0 * p;

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

she_ciphertext_t*
she_encrypt(she_public_key_t* pk, she_private_key_t* sk, BIT_ARRAY* m)
{
    // Encrypt array of bits
    //   pk: public key
    //   sk: private key
    //   m: array or bits
    //   n: array size

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
        mpz_t scratch;

        // Chooses random odd q from (2Z + 1) intersection [1, 2^gamma/p)
        mpz_init(scratch);
        mpz_ui_pow_ui(scratch, 2, gamma);
        mpz_class t(mpz_class(scratch) / *p);
        mpz_class q = _random_odd_mpz(1, t-1);
        mpz_clear(scratch);

        // Chooses random noise r from (-2s, 2s)
        mpz_init(scratch);
        mpz_ui_pow_ui(scratch, 2, s);
        mpz_class z(scratch);
        mpz_class r = _random_mpz(-z, z);

        // Encrypts m[i]
        res->data.push_back((q*(*p) + 2*r + bit_array_get_bit(m, i)) % (*x));
    }

    return res;
}

BIT_ARRAY*
she_decrypt(she_private_key_t* sk, she_ciphertext_t* c)
{
    // Decrypt array of bits
    //   sk: private key
    //   c: ciphertext

    if (!sk || !c) {
        return nullptr;
    }

    auto p = sk->p;

    unsigned int n = c->data.size();

    auto res = bit_array_create(n);

    for (int i=0; i<n; ++i) {
        // Decrypts c[i]
        mpz_class t = c->data[i] % (*p) % 2;
        bit_array_assign_bit(res, i, (char) !((bool) t.get_si()));
    }

    return res;
}

// ==========
// OPERATIONS
// ==========

she_ciphertext_t *
she_xor(she_public_key_t* pk, she_ciphertext_t* a, she_ciphertext_t* b)
{
    // Homomorphically XOR ciphertexts
    //   sk: private key
    //   a: ciphertext
    //   b: ciphertext

    if (!pk || !a || !b || a->data.size() != b->data.size()) {
        return nullptr;
    }

    auto x = pk->x;
    auto l = pk->l;

    auto res = new she_ciphertext_t();
    for (int i=0; i<l; ++i) {
        mpz_class t = (a->data[i] + b->data[i]) % (*x);
        res->data.push_back(t);
    }

    return res;
}

she_ciphertext_t*
she_xor1(she_public_key_t* pk, she_ciphertext_t* a, BIT_ARRAY* b)
{
    // Homomorphically XOR ciphertext and plaintext
    //   sk: private key
    //   a: ciphertext
    //   b: bit array
    //   n: array size

    bit_index_t n;
    if (!pk || !a || !b || a->data.size() != (n = bit_array_length(b))) {
        return nullptr;
    }

    auto x = pk->x;

    auto res = new she_ciphertext_t();
    for (int i=0; i<n; ++i) {
        mpz_class t = (a->data[i] + bit_array_get_bit(b, i)) % (*x);
        res->data.push_back(t);
    }

    return res;
}

she_ciphertext_t*
she_and(she_public_key_t* pk, she_ciphertext_t* a, she_ciphertext_t* b)
{
    // Homomorphically AND ciphertexts
    //   sk: private key
    //   a: ciphertext
    //   b: ciphertext

    if (a->data.size() != b->data.size()) {
        return nullptr;
    }

    auto x = pk->x;

    auto res = new she_ciphertext_t();

    for (int i=0; i<a->data.size(); ++i) {
        mpz_class t = (a->data[i] * b->data[i] + 1) % (*x);
        res->data.push_back(t);
    }

    return res;
}

she_ciphertext_t*
she_sumprod(she_public_key_t* pk, she_ciphertext_t* a, BIT_ARRAY* betas,
    unsigned int n, unsigned int l)
{
    // Homomorphically computes AND product of the sum of ciphertext `a` and
    // negated plaintexts `betas`
    //   pk: public key
    //   betas: number of plaintexts
    //   n: number of ciphertexts
    //   l: size of plaintext

    if (!pk || !a || !betas || n == 0 || bit_array_length(betas) != n*l) {
        return nullptr;
    }

    auto x = pk->x;

    auto res = new she_ciphertext_t();

    for (int i=0; i<n; ++i) {
        mpz_class acc = 1;
        for (int j=0; j<l; ++j) {
            auto beta = bit_array_get_bit(betas, i*l + j);
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
        acc += 1; acc %= (*x);
        (res->data).push_back(acc);
    }

    return res;
}

she_ciphertext_t*
she_dot(she_public_key_t* pk, she_ciphertext_t* g, BIT_ARRAY* b,
    unsigned int n, unsigned int m)
{
    // Dot product of `g` and each column of `b` matrix
    //   pk: public key
    //   g: ciphertext
    //   b: bit matrix
    //   n: number of rows
    //   m: number of columns

    if (!pk || !g || !b || n == 0 || m == 0 ||
        g->data.size() != n || bit_array_length(b) != n*m)
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
