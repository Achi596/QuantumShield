# Compiler flags and required libraries
CC = gcc
CFLAGS = -Iinclude -Wall
LDFLAGS = -lssl -lcrypto -ljansson

# Include src directory
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

# Target executable
hashsig: $(OBJ) main.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# List of object files
main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

# Housekeeping
clean:
	rm -f $(TARGET) $(OBJ) main.o bench.csv root.hex sig.bin xmss_key.bin xmss_state.dat *.json tests/time_test
