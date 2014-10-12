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

test: $(CPPTESTS) $(OBJECTS)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(LIB) $^ -o $(BUILDDIR)/tests
	@$(TESTSTARGET)

nosetests: $(LIBTARGET)
	@nosetests .

.PHONY: clean
