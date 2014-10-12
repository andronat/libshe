#ifndef __SHE_H__
#define __SHE_H__

#include <stdbool.h>


struct she_public_key_t;
struct she_private_key_t;
struct she_ciphertext_t;

// public_key_t, private_key_t
struct she_private_key_t* she_generate_private_key(unsigned int s, unsigned int l);
struct she_public_key_t* she_generate_public_key(struct she_private_key_t* sk);
void she_free_public_key(struct she_public_key_t* pk);
void she_free_private_key(struct she_public_key_t* sk);

char* she_serialize_public_key(struct she_public_key_t*);
char* she_serialize_private_key(struct she_private_key_t*);
struct she_public_key_t* she_deserialize_public_key(char*);
struct she_private_key_t* she_deserialize_private_key(char*);

// ciphertext_t
void she_free_ciphertext(struct she_ciphertext_t* c);

char* she_serialize_ciphertext(struct she_ciphertext_t* c);
struct she_ciphertext_t* she_deserialize_ciphertext(char* c);

// encryption
struct she_ciphertext_t* she_xor(struct she_public_key_t* pk, struct she_ciphertext_t* a, struct she_ciphertext_t* b);
struct she_ciphertext_t* she_xor1(struct she_public_key_t* pk, struct she_ciphertext_t* a, bool* b, unsigned int n);
struct she_ciphertext_t* she_and(struct she_public_key_t* pk, struct she_ciphertext_t* a, struct she_ciphertext_t* b);
struct she_ciphertext_t* she_prod(struct she_public_key_t* pk, struct she_ciphertext_t* cs, unsigned int n);

struct she_ciphertext_t* she_encrypt(struct she_public_key_t* pk, struct she_private_key_t* sk, bool* m, unsigned int n);
bool* she_decrypt(struct she_private_key_t* sk, struct she_ciphertext_t* c);


#endif
