CXX         := clang++
CFLAGS      := -g -Wall -fPIC --std=c++11 -O3  
BFLAGS      := -DBENCHMARK

BITARR      := lib/BitArray

LIB         := -lgmpxx -lgmp
INC         := -Iinclude -I$(BITARR)

SRCDIR      := src
BUILDDIR    := build

LIBTARGET   := $(BUILDDIR)/libshe.so
BLIBTARGET  := $(BUILDDIR)/libshebenchmark.so
TESTSTARGET := $(BUILDDIR)/tests
BITARRLIB   := $(BITARR)/libbitarr.a

SOURCES     := $(SRCDIR)/she.cpp
OBJECTS     := $(BUILDDIR)/she.o
BOBJECTS    := $(BUILDDIR)/shebenchmark.o
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

nosetests: $(LIBTARGET)
	@nosetests .

cleanBenchmark:
	$(RM) $(BLIBTARGET) $(BOBJECTS)
	$(RM) benchmark/*.txt

clean: cleanBenchmark
	$(RM) -r $(BUILDDIR)

benchmark: cleanBenchmark $(BLIBTARGET)

$(BLIBTARGET): $(BOBJECTS) $(BITARRLIB)
	@mkdir -p $(BUILDDIR)
	$(CXX) $(LIB) -shared $^ -o $(BLIBTARGET)

$(BOBJECTS): $(SOURCES) $(HEADERS)
	@mkdir -p $(BUILDDIR)
	$(CXX) $(CFLAGS) $(BFLAGS) $(INC) -c $(SOURCES) -o $@

.PHONY: clean
