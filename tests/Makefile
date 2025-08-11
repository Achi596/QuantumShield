# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../include
LDFLAGS = -lssl -lcrypto

# Reusisng source files from src/
SRC_DIR = ../src
SRC_OBJS = \
	$(SRC_DIR)/csprng.o \
	$(SRC_DIR)/hash.o \
	$(SRC_DIR)/merkle.o \
	$(SRC_DIR)/timer.o \
	$(SRC_DIR)/util.o \
	$(SRC_DIR)/wots.o \
	$(SRC_DIR)/xmss.o \
	$(SRC_DIR)/xmss_config.o \
	$(SRC_DIR)/xmss_eth.o \
	$(SRC_DIR)/xmss_wots.o

# Test source
TEST_SRC = time_test.c
TEST_BIN = time_test

# Default target
all: $(TEST_BIN)

# Build the test binary
$(TEST_BIN): $(TEST_SRC) $(SRC_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build object files from src/
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

# Housekeeping 
clean:
	rm -f $(TEST_BIN) $(SRC_OBJS)
.PHONY: all clean
