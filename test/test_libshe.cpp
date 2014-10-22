extern "C" {
    #include "she.h"
}

#include <iostream>
#include <cassert>

using namespace std;


void _print_block(string s) {
    for (int i=0; i<s.size(); ++i) {
        if (i != 0 && (i % 64 == 0)) {
            cout << endl;
        }
        cout << s[i];
    }
    cout << endl;
}


ostream& operator<<(ostream& os, const BIT_ARRAY* bar) {
    for (int i=0; i<bit_array_length(bar); ++i) {
        os << (int) bit_array_get_bit(bar, i);
    }
    return os;
}


int main() {
    // Generate keys
    int s = 60;
    int l = 8;
    auto sk = she_generate_private_key(s, l);
    auto pk = she_generate_public_key(sk);

    // Print keys
    cout << "-----YAY BEGIN BLINDSTORE PRIVATE KEY BLOCK-----" << endl;
    // Version is variant Dijk-Gentry-Halevi-Vaikantanuthan with no compression
    cout << "Version: V-DGHV NC " << s << endl << endl;
    auto serialized_sk = she_serialize_private_key(sk);
    _print_block(serialized_sk);
    cout << "-----END BLINDSTORE PRIVATE KEY BLOCK SO CRYPTO MUCH WOW-----" << endl << endl;

    cout << "-----YAY BEGIN BLINDSTORE PUBLIC KEY BLOCK-----" << endl;
    cout << "Version: V-DGHV NC " << s << endl << endl;
    char* serialized_pk = she_serialize_public_key(pk);
    _print_block(serialized_pk);
    delete serialized_pk;
    cout << "-----END BLINDSTORE PUBLIC KEY BLOCK SO CRYPTO MUCH WOW-----" << endl;

    cout << endl << endl;

    // Encrypt
    auto m1 = bit_array_create(8);
    // 1, 0, 0, 1, 0, 1, 0, 1
    bit_array_set_bits(m1, 4,  0, 3, 5, 7);
    auto a = she_encrypt(pk, sk, m1);

    // 1, 0, 0, 1, 0, 1, 0, 0
    auto m2 = bit_array_create(8);
    bit_array_set_bits(m2, 3,  0, 3, 5);
    auto b = she_encrypt(pk, sk, m2);

    // 1, 1, 1, 1, 1, 1, 1, 1
    auto m3 = bit_array_create(8);
    bit_array_set_all(m3);
    auto x = she_encrypt(pk, sk, m3);

    // Print encrypted message
    cout << "-----BEGIN SUPER CRYPTO BLINDSTORE MESSAGE-----" << endl;
    cout << "Version: V-DGHV NC " << s << endl << endl;
    auto serialized_ciphertext = she_serialize_ciphertext(a);
    _print_block(serialized_ciphertext);
    delete serialized_ciphertext;
    cout << "-----END BLINDSTORE MESSAGE-----" << endl;

    cout << endl << endl;

    // Decrypt
    {
        auto w = she_decrypt(sk, a);

        cout << "Message" << endl;
        cout << m1 << endl;

        cout << "Decrypted message:" << endl;
        cout << w << endl << endl;
    }

    // Addition
    {
        auto c = she_xor(pk, a, b);
        auto w = she_decrypt(sk, c);

        cout << "Homomorphic addition:" << endl;
        cout << w << endl << endl;

        she_free_ciphertext(c);
    }

    // Multiplication
    {
        auto d = she_and(pk, a, b);
        auto w = she_decrypt(sk, d);

        cout << "Homomorphic multiplication:" << endl;
        cout << w << endl << endl;

        she_free_ciphertext(d);
    }

    // Sum-Product
    {
        auto m = bit_array_create(8);
        bit_array_set_bits(m, 7,  0, 1, 2, 3, 4, 5, 6);
        auto a = she_encrypt(pk, sk, m);

        auto x = bit_array_create(16);
        bit_array_set_bits(x, 7,  0, 1, 2, 3, 4, 5, 6);
        auto y = bit_array_create(16);
        bit_array_set_all(y);

        auto p = she_sumprod(pk, a, x, 2, 8);
        auto q = she_sumprod(pk, a, y, 2, 8);

        auto z = she_decrypt(sk, p);
        auto h = she_decrypt(sk, q);

        cout << "Homomorphic sum-products:" << endl;
        cout << z << endl;
        cout << h << endl << endl;
    }

    // Dot
    {
        auto m1 = bit_array_create(2);
        auto m2 = bit_array_create(2);
        bit_array_set_bit(m2, 0);
        auto m3 = bit_array_create(2);
        bit_array_set_bit(m3, 1);
        auto db = bit_array_create(16);
        bit_array_set_bits(db, 8,  0, 2, 4, 6, 9, 11, 13, 15);

        auto g1 = she_encrypt(pk, sk, m1);
        auto g2 = she_encrypt(pk, sk, m2);
        auto g3 = she_encrypt(pk, sk, m3);

        auto p = she_dot(pk, g1, db, 2, 8);
        auto q = she_dot(pk, g2, db, 2, 8);
        auto r = she_dot(pk, g3, db, 2, 8);

        auto z = she_decrypt(sk, p);
        auto h = she_decrypt(sk, q);
        auto u = she_decrypt(sk, r);

        cout << "Homomorphic dot:" << endl;
        cout << z << endl;
        cout << h << endl;
        cout << u << endl;
    }

    // Destructors
    she_free_public_key(pk);
    she_free_private_key(sk);

    she_free_ciphertext(a);
    she_free_ciphertext(b);
    she_free_ciphertext(x);

    return 0;
}
