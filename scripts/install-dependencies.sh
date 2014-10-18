mkdir -p lib
cd lib

# Download
if [ ! -f "gmp-6.0.0a.tar.lz" ]; then
    wget https://gmplib.org/download/gmp/gmp-6.0.0a.tar.lz
fi

# GMP
if [ ! -d "gmp-6.0.0" ]; then
    lzip -d gmp-6.0.0a.tar.lz
    tar xf gmp-6.0.0a.tar
fi

cd gmp-6.0.0
./configure
make
make check
sudo make install
sudo ldconfig
cd ..
