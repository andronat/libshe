#CXX         := clang++
CFLAGS      := -g -Wall -fPIC --std=c++11 -O3

BITARR      := lib/BitArray

LIB         := -lgmpxx -lgmp
INC         := -Iinclude -I$(BITARR)

SRCDIR      := src
BUILDDIR    := build

LIBTARGET   := $(BUILDDIR)/libshe.so
TESTSTARGET := $(BUILDDIR)/tests
BITARRLIB   := $(BITARR)/libbitarr.a

SOURCES     := $(SRCDIR)/she.cpp
OBJECTS     := $(BUILDDIR)/she.o
HEADERS     := include/she.h


all: $(LIBTARGET)

$(LIBTARGET): $(OBJECTS) $(BITARRLIB)
	@mkdir -p $(BUILDDIR)
	$(CXX) $(LIB) -shared $^ -o $(LIBTARGET)

$(OBJECTS): $(SOURCES) $(HEADERS)
	@mkdir -p $(BUILDDIR)
	$(CXX) $(CFLAGS) $(INC) -c $(SOURCES) -o $@

$(BITARRLIB):
	$(MAKE) -C $(BITARR)

clean:
	@echo "Cleaning..."
	$(RM) -r $(BUILDDIR)

nosetests: $(LIBTARGET)
	@nosetests .

.PHONY: clean
