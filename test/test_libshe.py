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

def test_make_she_plaintext():
    a = [[1,0,0],[0,1,0],[0,0,1]]
    m = make_she_plaintext(3, a)
    for i, part in enumerate(a):
        for j, bit in enumerate(part):
            assert_equals(lib.she_plaintext_get_bit(m, i, j), bit)


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
        self.sk = lib.she_generate_private_key(60, 8)
        self.pk = lib.she_generate_public_key(self.sk)
        self.raw = [1, 0, 0, 1, 0, 1, 0, 1]
        self.data = make_bit_array(self.raw)

    def test_encryption(self):
        lib.she_encrypt(self.pk, self.sk, self.data)

    def test_decryption(self):
        for i in range(100):
            ctxt = lib.she_encrypt(self.pk, self.sk, self.data)
            ptxt = lib.she_decrypt(self.sk, ctxt)
            assert_equals(self.raw, make_list_from_bit_array(ptxt))


class TestPIR(object):

    def setup(self):
        self.n_tests = 1
        # Bit lengths of index
        self.l = 20 
        self.sk = lib.she_generate_private_key(60, self.l)
        self.pk = lib.she_generate_public_key(self.sk)
        # Record size in bits
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

    def test_gamma0(self):
        k = 0
        gamma = self.make_gamma(k)
        assert_equals(make_list_from_bit_array(
            lib.she_decrypt(self.sk, gamma)),
            make_index_vector(k, size=self.n))

    def test_gamma1(self):
        k = 1
        gamma = self.make_gamma(k)
        assert_equals(make_list_from_bit_array(
            lib.she_decrypt(self.sk, gamma)),
            make_index_vector(k, size=self.n))

    def test_gamma2(self):
        k = 2
        gamma = self.make_gamma(k)
        assert_equals(make_list_from_bit_array(
            lib.she_decrypt(self.sk, gamma)),
            make_index_vector(k, size=self.n))

    def test_gamma3(self):
        k = 3
        gamma = self.make_gamma(k)
        assert_equals(make_list_from_bit_array(
            lib.she_decrypt(self.sk, gamma)),
            make_index_vector(k, self.n))

    def test_query0(self):
        k = 0
        gamma = lib.she_encrypt(self.pk, self.sk,
                                make_bit_array(make_index_vector(k, self.n)))
        response = self.make_query(k, gamma)
        assert_equals(response, self.raw[k])

    def test_query1(self):
        k = 1
        gamma = lib.she_encrypt(self.pk, self.sk,
                                make_bit_array(make_index_vector(k, self.n)))
        response = self.make_query(k, gamma)
        assert_equals(response, self.raw[k])

    def test_query2(self):
        k = 2
        gamma = lib.she_encrypt(self.pk, self.sk,
                                make_bit_array(make_index_vector(k, self.n)))
        response = self.make_query(k, gamma)
        assert_equals(response, self.raw[k])

    def test_query3(self):
        k = 3
        gamma = lib.she_encrypt(self.pk, self.sk,
                                make_bit_array(make_index_vector(k, self.n)))
        response = self.make_query(k, gamma)
        assert_equals(response, self.raw[k])

    def test_full_query0(self):
        for i in range(self.n_tests):
            k = 0
            response = self.make_query(k)
            assert_equals(response, self.raw[k])

    def test_full_query1(self):
        for i in range(self.n_tests):
            k = 1
            response = self.make_query(k)
            assert_equals(response, self.raw[k])

    def test_full_query2(self):
        for i in range(self.n_tests):
            k = 2
            response = self.make_query(k)
            assert_equals(response, self.raw[k])

    def test_full_query3(self):
        for i in range(self.n_tests):
            k = 3
            response = self.make_query(k)
            assert_equals(response, self.raw[k])


class TestPIRThreaded(object):

    def setup(self):
        # bit length of indices and data records at the same time
        self.l = 8
        self.sk = lib.she_generate_private_key(128, self.l)
        self.pk = lib.she_generate_public_key(self.sk)
        # data, not splitted, used for comparing later
        self.raw = [[0, 1, 0, 1, 1, 0, 1, 0],
                    [1, 0, 0, 0, 0, 0, 0, 1],
                    [1, 0, 1, 1, 1, 1, 0, 1],
                    [1, 0, 1, 1, 1, 1, 0, 1],
                    [1, 0, 1, 1, 1, 1, 0, 1],
                    [1, 0, 1, 1, 1, 1, 0, 1],
                    [1, 0, 1, 1, 1, 1, 0, 1],
                    [1, 0, 1, 1, 1, 1, 0, 1],
                    [1, 0, 1, 1, 1, 1, 0, 1],
                    [0, 0, 0, 0, 1, 0, 1, 0]]
        # number of records in the database
        self.n = len(self.raw)
        # database split into 3 parts
        self.raw_split = [self.raw[0:3],
                          self.raw[3:4],
                          self.raw[4:7],
                          self.raw[7:]]
        self.number_of_parts = len(self.raw_split)
        self.size = 8

        self.data = []
        self.indices = []
        part_start_index = 0
        for i, part in enumerate(self.raw_split):
            self.data.append(make_she_plaintext(self.l, part))
            # construct the indices
            self.indices.append(make_she_plaintext(self.l, [binary(j, size=self.l) for j in range(part_start_index, part_start_index+len(part))]))
            part_start_index += len(part)

    def make_gamma_part(self, index, part_of_database):
        plain_index = make_bit_array(binary(index, size=self.l))
        c = lib.she_encrypt(self.pk, self.sk, plain_index)
        ctxt = lib.she_sumprod(self.pk, c, self.indices[part_of_database])
        return ctxt

    def get_response_part(self, index, part_of_database):
        gamma = self.make_gamma_part(index, part_of_database)
        return lib.she_dot(self.pk, gamma, self.data[part_of_database])

    def get_response(self, index):
        responses = lib.she_allocate_ciphertext_array(self.number_of_parts)

        # this loop should be put into seperate threads
        for part_number in range(self.number_of_parts):
            response = self.get_response_part(index, part_number)
            lib.she_write_to_ciphertext_array(responses, part_number, response)

        ctxt = lib.she_xor(self.pk, responses, self.number_of_parts, self.l)
        return ctxt

    def test_full_query(self):
        for index in range(self.n):
            ctxt = self.get_response(index)
            ptxt = lib.she_decrypt(self.sk, ctxt)
            assert_equals(make_list_from_bit_array(ptxt), self.raw[index])


class TestCiphertextXOR(object):

    def setup(self):
        self.l = 8
        self.sk = lib.she_generate_private_key(128, self.l)
        self.pk = lib.she_generate_public_key(self.sk)
        self.raw = [[0, 1, 0, 1, 1, 0, 1, 0],
                    [1, 0, 0, 1, 0, 0, 0, 0],
                    [1, 0, 1, 1, 1, 1, 0, 1],
                    [0, 0, 0, 0, 1, 0, 0, 0]]
        self.n = len(self.raw)
        self.size = 8
        self.ciphertexts = lib.she_allocate_ciphertext_array(self.n)

        self.data = [lib.she_encrypt(self.pk, self.sk, make_bit_array(row)) for row in self.raw]

    def test_xor_ciphertexts(self):
        for i, row in enumerate(self.data):
            lib.she_write_to_ciphertext_array(self.ciphertexts, i, row)
        ctxt = lib.she_xor(self.pk, self.ciphertexts, self.n, self.size)
        ptxt = lib.she_decrypt(self.sk, ctxt)
        assert_equals(make_list_from_bit_array(ptxt), [0, 1, 1, 1, 1, 1, 1, 1])

    def teardown(self):
        lib.she_free_ciphertext_array(self.ciphertexts, self.n)
