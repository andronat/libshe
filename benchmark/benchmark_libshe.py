import ctypes
from itertools import chain

from nose.tools import *


lib = ctypes.CDLL('build/libshebenchmark.so')


def binary(num, size=8):
    full_binary = [int(d) for d in bin(num)[2:]]
    n = len(full_binary)
    if n >= size:
        return full_binary[-size:]
    else:
        return [0] * (size - n) + full_binary


def make_index_vector(i, size):
    return [1 if j == i else 0 for j in range(size)]


def make_bit_array(bits):
    indices = [i for i, _ in filter(lambda tpl: tpl[1] == 1, enumerate(bits))]
    bar = lib.bit_array_create(len(bits))
    lib.bit_array_set_bits(bar, len(indices), *indices)
    return bar

# make she plaintext struct from 2d list
def make_she_plaintext(chunk_size, bits):
    plaintext = lib.she_make_plaintext(chunk_size)
    for record in bits:
        # record is a list of bits
        lib.she_plaintext_append_bit_array(plaintext, make_bit_array(record))
    return plaintext

def make_list_from_bit_array(bit_array):
    n = lib.bit_array_length(bit_array)
    return [int(lib.bit_array_get_bit(bit_array, i))
            for i in range(n)]


def flatten(nested):
    return list(chain.from_iterable(nested))


def test_bit_array_utils():
    a = [1, 0, 0, 1, 0, 1, 0, 1]
    m = make_bit_array(a)
    assert_equals(make_list_from_bit_array(m), a)


def test_binary():
    assert_equals(binary(10, 8), [0, 0, 0, 0, 1, 0, 1, 0])


class TestPIR(object):

    def setup(self):
        self.n_tests = 1
        # Bit lengths of index (chunk size of index)
        self.l = 50
        self.sk = lib.she_generate_private_key(60, self.l)
        self.pk = lib.she_generate_public_key(self.sk)
        # Record size in bits (chunk size of the data)
        self.size = 1024 * 8 
        # Number of records
        self.n = 10  
        # Database generation
        self.raw = [[1] * self.size] * self.n
        # Required datastructure for libshe library
        self.data = make_she_plaintext(self.size, self.raw) 
        # Database index generation 
        self.indices = make_she_plaintext(self.l, 
            [binary(i, size=self.l) for i in range(self.n)])

    def make_gamma(self, i):
        plain_index = make_bit_array(binary(i, size=self.l))
        c = lib.she_encrypt(self.pk, self.sk, plain_index)
        ctxt = lib.she_sumprod(self.pk, c, self.indices)
        return ctxt

    def make_query(self, i, gamma=None):
        if gamma is None:
            gamma = self.make_gamma(i)
        ctxt = lib.she_dot(self.pk, gamma, self.data)
        ptxt = lib.she_decrypt(self.sk, ctxt)
        return make_list_from_bit_array(ptxt)

    def test_full_query0(self):
        for i in range(self.n_tests):
            k = 0
            response = self.make_query(k)
            assert_equals(response, self.raw[k])

