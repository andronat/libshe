import ctypes
from itertools import chain

from nose.tools import *


lib = ctypes.CDLL('build/libshe.so')


def binary(num, size=8):
    full_binary = [int(d) for d in bin(num)[2:]]
    n = len(full_binary)
    if n >= size:
        return full_binary[-size:]
    else:
        return [0] * (size - n) + full_binary


def make_index_vector(i, size):
    return [1 if j == i else 0 for j in range(size)]


def make_plaintext(bits):
    indices = [i for i, _ in filter(lambda tpl: tpl[1] == 1, enumerate(bits))]
    bar = lib.bit_array_create(len(bits))
    lib.bit_array_set_bits(bar, len(indices), *indices)
    return bar


def make_list_from_plaintext(plaintext):
    n = lib.bit_array_length(plaintext)
    return [int(lib.bit_array_get_bit(plaintext, i))
            for i in range(n)]


def flatten(nested):
    return list(chain.from_iterable(nested))


def test_plaintext_utils():
    a = [1, 0, 0, 1, 0, 1, 0, 1]
    m = make_plaintext(a)
    assert_equals(make_list_from_plaintext(m), a)


def test_binary():
    assert_equals(binary(10, 8), [0, 0, 0, 0, 1, 0, 1, 0])


class TestKeygen(object):

    def setup(self):
        self.sk = lib.she_generate_private_key(128, 32)
        self.pk = lib.she_generate_public_key(self.sk)

    def test_destructors(self):
        lib.she_free_private_key(self.sk)
        lib.she_free_public_key(self.pk)

    def generate_sk(self, s, l):
        return lib.she_generate_private_key(s, l)

    def test_bad_parameters0(self):
        assert_equals(self.generate_sk(0, 32), 0)

    def test_bad_parameters1(self):
        assert_equals(self.generate_sk(128, 0), 0)

    def test_bad_parameters2(self):
        assert_equals(self.generate_sk(0, 0), 0)


class TestEncryption(object):

    def setup(self):
        self.sk = lib.she_generate_private_key(128, 8)
        self.pk = lib.she_generate_public_key(self.sk)
        self.raw = [1, 0, 0, 1, 0, 1, 0, 1]
        self.data = make_plaintext(self.raw)

    def test_encryption(self):
        lib.she_encrypt(self.pk, self.sk, self.data)

    def test_decryption(self):
        ctxt = lib.she_encrypt(self.pk, self.sk, self.data)
        ptxt = lib.she_decrypt(self.sk, ctxt)
        assert_equals(self.raw, make_list_from_plaintext(ptxt))


class TestSumprod(object):

    def setup(self):
        self.sk = lib.she_generate_private_key(128, 4)
        self.pk = lib.she_generate_public_key(self.sk)
        self.raw = [binary(i, size=4) for i in range(4)]
        self.indices = make_plaintext(flatten(self.raw))

    def make_gamma(self, i):
        plain_index = make_plaintext(binary(i, size=4))
        c = lib.she_encrypt(self.pk, self.sk, plain_index)
        ctxt = lib.she_sumprod(self.pk, c, self.indices, len(self.raw), 4)
        ptxt = lib.she_decrypt(self.sk, ctxt)
        return make_list_from_plaintext(ptxt)

    def test_gamma0(self):
        assert_equals(self.make_gamma(0), make_index_vector(0, size=4))

    def test_gamma1(self):
        assert_equals(self.make_gamma(1), make_index_vector(1, size=4))

    def test_gamma2(self):
        assert_equals(self.make_gamma(2), make_index_vector(2, size=4))

    def test_gamma3(self):
        assert_equals(self.make_gamma(3), make_index_vector(3, size=4))


class TestDot(object):

    def setup(self):
        self.sk = lib.she_generate_private_key(128, 8)
        self.pk = lib.she_generate_public_key(self.sk)
        self.raw = [[0, 1, 0, 1, 1, 0, 1, 0],
                    [1, 0, 0, 0, 0, 0, 0, 1],
                    [1, 0, 1, 1, 1, 1, 0, 1],
                    [1, 0, 1, 1, 1, 1, 0, 1]]
        self.n = len(self.raw)
        self.data = make_plaintext(flatten(self.raw))

    def make_query(self, i):
        index_vector = make_plaintext(make_index_vector(i, size=self.n))
        gamma = lib.she_encrypt(self.pk, self.sk, index_vector)
        ctxt = lib.she_dot(self.pk, gamma, self.data, self.n, 8)
        ptxt = lib.she_decrypt(self.sk, ctxt)
        return make_list_from_plaintext(ptxt)

    def test_dot0(self):
        assert_equals(self.raw[0], self.make_query(0))

    def test_dot1(self):
        assert_equals(self.raw[1], self.make_query(1))

    def test_dot2(self):
        assert_equals(self.raw[2], self.make_query(2))

    def test_dot3(self):
        assert_equals(self.raw[3], self.make_query(3))
