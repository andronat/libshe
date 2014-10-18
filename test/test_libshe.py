from nose.tools import *

import ctypes

lib = ctypes.CDLL('build/libshe.so')


def make_plaintext(bits):
    indices = [i for i, _ in filter(lambda tpl: tpl[1] == 1, enumerate(bits))]
    bar = lib.bit_array_create(len(bits))
    lib.bit_array_set_bits(bar, len(indices), *indices)
    return bar

def make_list(plaintext):
    n = lib.bit_array_length(plaintext)
    return [int(lib.bit_array_get_bit(plaintext, i))
        for i in range(n)]

def test_utils():
    a =  [1, 0, 0, 1, 0, 1, 0, 1]
    m = make_plaintext(a)
    assert_equals(make_list(m), a)

class TestKeygen(object):

    def setup(self):
        self.sk = lib.she_generate_private_key(128, 32)
        self.pk = lib.she_generate_public_key(self.sk)

    def test_destructors(self):
        lib.she_free_private_key(self.sk)
        lib.she_free_public_key(self.pk)

    def test_bad_parameters(self):
        bad_params = [
            (0, 32),
            (128, 0),
            (0, 0)
        ]
        for s, l in bad_params:
            assert_equals(lib.she_generate_private_key(s, l), 0)


class TestEncryption(object):

    def setup(self):
        self.sk = lib.she_generate_private_key(128, 8)
        self.pk = lib.she_generate_public_key(self.sk)
        self.msg = [1, 0, 0, 1, 0, 1, 0, 1]

    def test_encryption(self):
        lib.she_encrypt(self.pk, self.sk, make_plaintext(self.msg))

    @nottest
    def test_decryption(self):
        ctxt = lib.she_encrypt(self.pk, self.sk, make_plaintext(self.msg))
        lib.she_decrypt.restype = ctypes.c_bool * len(self.msg)
        decrypted = make_list(lib.she_decrypt(self.sk, ctxt))
        assert_equals(self.msg, decrypted)
