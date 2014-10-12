CC          := clang++
CFLAGS      := -g -Wall -fPIC --std=c++11
LIB         := -lgmp
INC         := -Iinclude

SRCDIR      := src
BUILDDIR    := build

LIBTARGET   := $(BUILDDIR)/libshe.so
TESTSTARGET := $(BUILDDIR)/tests

SOURCES := $(SRCDIR)/she.cpp
OBJECTS := $(BUILDDIR)/she.o
TESTOBJECTS := $(BUILDDIR)/test.o
CPPTESTS := test/test_libshe.cpp


all: $(LIBTARGET)

$(LIBTARGET): $(OBJECTS)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(INC) $^ -shared  $(LIB) -o $(LIBTARGET)

$(OBJECTS): $(SOURCES)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@echo "Cleaning..."
	$(RM) -r $(BUILDDIR)

test: $(TESTOBJECTS) $(OBJECTS)
	$(CC) $(CFLAGS) $(INC) $(LIB) $^ -o $(BUILDDIR)/tests
	@$(TESTSTARGET)

$(TESTOBJECTS): $(CPPTESTS)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

nosetests: $(LIBTARGET)
	@nosetests .

.PHONY: clean
