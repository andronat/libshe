extern "C" {
    #include "../include/she.h"
}

#include <iostream>

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
    delete serialized_sk;
    cout << "-----END BLINDSTORE PRIVATE KEY BLOCK SO CRYPTO MUCH WOW-----" << endl << endl;

    cout << "-----YAY BEGIN BLINDSTORE PUBLIC KEY BLOCK-----" << endl;
    cout << "Version: V-DGHV NC " << s << endl << endl;
    char* serialized_pk = she_serialize_public_key(pk);
    _print_block(serialized_pk);
    delete serialized_pk;
    cout << "-----END BLINDSTORE PUBLIC KEY BLOCK SO CRYPTO MUCH WOW-----" << endl;

    cout << endl << endl;

    // Encrypt
    bool m1[] = {1, 0, 0, 1, 0, 1, 0, 1};
    auto a = she_encrypt(pk, sk, m1, 8);

    bool m2[] = {1, 0, 0, 1, 0, 1, 0, 0};
    auto b = she_encrypt(pk, sk, m2, 8);

    bool m3[] = {1, 1, 1, 1, 1, 1, 1, 1};
    auto x = she_encrypt(pk, sk, m3, 8);

    // Print encrypted message
    cout << "-----BEGIN SUPER CRYPTO BLINDSTORE MESSAGE-----" << endl;
    cout << "Version: V-DGHV NC " << s << endl << endl;
    auto serialized_ciphertext = she_serialize_ciphertext(a);
    _print_block(serialized_ciphertext);
    delete serialized_ciphertext;
    cout << "-----END BLINDSTORE MESSAGE-----" << endl;

    cout << endl << endl;

    // Decrypt
    bool* w = she_decrypt(sk, a);

    cout << "Decrypted message:" << endl;
    for (int i=0; i<l; ++i) {
        cout << w[i];
    }
    cout << endl << endl;

    // Addition
    auto c = she_xor(pk, a, b);
    w = she_decrypt(sk, c);

    cout << "Homomorphic addition:" << endl;
    for (int i=0; i<l; ++i) {
        cout << w[i];
    }
    cout << endl << endl;

    // Multiplication
    auto d = she_and(pk, a, b);
    w = she_decrypt(sk, d);

    cout << "Homomorphic multiplication:" << endl;
    for (int i=0; i<l; ++i) {
        cout << w[i];
    }
    cout << endl << endl;

    // Product
    auto p = she_prod(pk, c, 1);
    auto q = she_prod(pk, x, 1);
    bool *z = she_decrypt(sk, p);
    bool *h = she_decrypt(sk, q);
    cout << "Homomorphic products:" << endl;
    cout << z[0] << endl << endl;
    cout << h[0] << endl << endl;

    return 0;
}
