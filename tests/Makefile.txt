# Compiler and flags
CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

# --- List of all executables to build ---
TARGETS = hashsig time_test

# --- Object File Definitions ---
# Note the different paths for main.o vs. other objects

# Object files that live in the src/ directory
COMMON_OBJS = \
	src/csprng.o \
	src/hash.o \
	src/merkle.o \
	src/timer.o \
	src/util.o \
	src/wots.o \
	src/xmss.o \
	src/xmss_config.o \
	src/xmss_eth.o \
	src/xmss_wots.o

# Object files needed specifically for the 'hashsig' executable
# Note: main.o is listed first as it's in the root dir
HASHSIG_DEPS = main.o src/benchmark.o $(COMMON_OBJS)

# Object files needed specifically for the 'time_test' executable
TIMETEST_DEPS = src/time_test.o $(COMMON_OBJS)


# --- Build Rules ---

# Default target when you run 'make'
all: $(TARGETS)

# Rule to build the 'hashsig' executable
hashsig: $(HASHSIG_DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Rule to build the 'time_test' executable
time_test: $(TIMETEST_DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)


# --- Compilation Rules ---

# Explicit rule for main.o, since main.c is in the root directory
main.o: main.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Explicit rule for time_test.o, since time_test.c is in the src/ directory
src/time_test.o: src/time_test.c
	$(CC) $(CFLAGS) -c -o $@ $<

# A pattern rule for all other .c files inside the src/ directory
src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<


# --- Housekeeping ---

# Rule to clean up all generated files from all locations
clean:
	-rm -f $(TARGETS) main.o src/*.o
	-rm -f *.bin *.dat *.hex *.csv

# Declare targets that are not files
.PHONY: all clean