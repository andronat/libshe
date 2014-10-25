CXX         := clang++
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

TESTOBJECTS := $(BUILDDIR)/test.o
CPPTESTS    := test/test_libshe.cpp


all: $(LIBTARGET)

$(LIBTARGET): $(OBJECTS) $(BITARRLIB)
	@mkdir -p $(BUILDDIR)
	$(CXX) $(LIB) -shared $^ -o $(LIBTARGET)

$(OBJECTS): $(SOURCES)
	@mkdir -p $(BUILDDIR)
	$(CXX) $(CFLAGS) $(INC) -c $^ -o $@

$(BITARRLIB):
	$(MAKE) -C $(BITARR)

clean:
	@echo "Cleaning..."
	$(RM) -r $(BUILDDIR)

test: $(LIBTARGET) $(TESTOBJECTS)
	$(CXX) $(CFLAGS) $(INC) $(LIB) -L$(BUILDDIR) $^ -o $(BUILDDIR)/tests
	@$(TESTSTARGET)

$(TESTOBJECTS): $(BITARRLIB) $(CPPTESTS)
	@mkdir -p $(BUILDDIR)
	$(CXX) $(CFLAGS) $(INC) -c $^ -o $@

nosetests: $(LIBTARGET)
	@nosetests .

.PHONY: clean
