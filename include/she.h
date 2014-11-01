#ifndef __SHE_H__
#define __SHE_H__

#include "bit_array.h"


struct she_public_key_t;
struct she_private_key_t;
struct she_ciphertext_t;
struct she_plaintext_t;

// public_key_t, private_key_t
struct she_private_key_t* she_generate_private_key(unsigned int s, unsigned int l);
struct she_public_key_t* she_generate_public_key(struct she_private_key_t* sk);
void she_free_public_key(struct she_public_key_t* pk);
void she_free_private_key(struct she_private_key_t* sk);

char* she_serialize_public_key(struct she_public_key_t*);
char* she_serialize_private_key(struct she_private_key_t*);
struct she_public_key_t* she_deserialize_public_key(char*);
struct she_private_key_t* she_deserialize_private_key(char*);

// ciphertext_t
void she_free_ciphertext(struct she_ciphertext_t* c);

char* she_serialize_ciphertext(struct she_ciphertext_t* c);
she_ciphertext_t* she_deserialize_ciphertext(char* c);

// operations
struct she_ciphertext_t* she_xor(she_public_key_t* pk, she_ciphertext_t** cs, unsigned int n, unsigned m);
struct she_ciphertext_t* she_sumprod(struct she_public_key_t* pk, struct she_ciphertext_t* a, she_plaintext_t* b);
struct she_ciphertext_t* she_dot(she_public_key_t* pk, she_ciphertext_t* g, she_plaintext_t* b);

// encryption
struct she_ciphertext_t* she_encrypt(struct she_public_key_t* pk, struct she_private_key_t* sk, BIT_ARRAY* m);
BIT_ARRAY* she_decrypt(struct she_private_key_t* sk, struct she_ciphertext_t* c);

// ciphertext array
struct she_ciphertext_t** she_allocate_ciphertext_array(unsigned int n);
void she_write_to_ciphertext_array(she_ciphertext_t** cs, unsigned int i, struct she_ciphertext_t* c);
void she_free_ciphertext_array(she_ciphertext_t** cs, unsigned int n);

// plaintext shard
she_plaintext_t* she_make_plaintext(unsigned int chunk_size);
char she_plaintext_get_bit(she_plaintext_t* plaintext, unsigned int row, unsigned int column);
void she_plaintext_append_bit_array(she_plaintext_t* plaintext, BIT_ARRAY* m);
void she_plaintext_update_bit_array(she_plaintext_t* plaintext, unsigned int row, BIT_ARRAY* m);
void she_free_plaintext(she_plaintext_t* plaintext);

#endif
