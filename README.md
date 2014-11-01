## Overview

This is an implementation of the V-DGHV scheme of somewhat homomorphic encryption presented in [1]. The library presented here is beta software and should not be used for any mission critical applications. No warranty expressed or implied is given.

## Installation

```
# The GNU GMP library must be installed and included in your path. See: gmplib.org
# Make sure to configure it as:
./configure --enable-cxx
# before making and installing.

# You can install GMP and its headers on Debian systems using:
sudo apt-get install libgmp-dev

# Install nose to be able to be running the tests
sudo pip install nose

# Recursively clone the repository, as libraries are included as submodules
git clone --recursive git@github.com:blindstore/libshe.git`

# Build the library
cd libshe
make

# Run the tests
make nosetests
```

## References

[1] Yi, Xun; Kaosar, Mohammed Golam; Paulet, Russell; Bertino, Elisa, ["Single-Database Private Information Retrieval from Fully Homomorphic Encryption"](http://dx.doi.org/10.1109/TKDE.2012.90), Knowledge and Data Engineering, IEEE Transactions on , vol.25, no.5, pp.1125,1134, May 2013
