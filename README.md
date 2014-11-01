
## Installation
    
   # The GNU GMP library must be installed and included in your path. See: gmplib.org
   # Make sure to configure it as:
   ./configure --enable-cxx 
   # before making and installing. 

   # You can install GMP on Debian systems using:
   sudo apt-get install libgmp-dev

   # Install nose
   sudo pip install nose

   # Recursively clone the repo
   git clone --recursive git@github.com:blindstore/libshe.git`

   # Build the library
   cd libshe
   make

   # Run tests
   make nosetests
