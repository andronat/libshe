#include <iostream>
#include <cassert>
#include <array>
#include <vector>
#include <she.h>
#include <bit_array.h>


// 1) make
// 2) g++ -std=c++11 -I lib/BitArray/ -I ./include/ -L ./build/ -lshe -Wall -g -o test/test_libshe test/test_libshe.cpp

void test_PlainText_append_operator() {
    std::vector<std::vector<int>> data {
        {1,0,0},
        {0,1,0},
        {0,0,1}
    };

    PlainText plntxt;

    BIT_ARRAY* ba = bit_array_create(3);
    bit_array_set_bit(ba, 0);
    plntxt += ba;
    ba = bit_array_create(3);
    bit_array_set_bit(ba, 1);
    plntxt += ba;
    ba = bit_array_create(3);
    bit_array_set_bit(ba, 2);
    plntxt += ba;

    assert(plntxt.entry_count() == 3);
    assert(plntxt.bit_size() == 9);
    std::cout << "Number of arrays: " << plntxt.entry_count()
          << " Number of bits: " << plntxt.bit_size() << std::endl;

    for (int i=0; i<data.size(); i++) {
        for (int g=0; g<data[i].size(); g++) {
            assert(plntxt.get_bit(i,g) == data[i][g]);
        }
    }

    std::cout << "PlainText append operator += works properly!" << std::endl;
}

void test_PlainText_constractor() {
    std::vector<std::vector<int>> data {
        {1,0,0},
        {0,1,0},
        {0,0,1}
    };

    PlainText plntxt(data);

    assert(plntxt.entry_count() == 3);
    assert(plntxt.bit_size() == 9);
    std::cout << "Number of arrays: " << plntxt.entry_count()
          << " Number of bits: " << plntxt.bit_size() << std::endl;

    for (int i=0; i<data.size(); i++) {
        for (int g=0; g<data[i].size(); g++) {
            assert(plntxt.get_bit(i,g) == data[i][g]);
        }
    }

    std::cout << "PlainText constractor works properly!" << std::endl;
}

int main() {
    test_PlainText_constractor();
    test_PlainText_append_operator();
    return 0;
}
