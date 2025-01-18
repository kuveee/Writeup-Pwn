.PHONY: all clean

CC = gcc
CFLAGS = -Wall -O0

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

vuln: main.o
	$(CC) $(CFLAGS) -o $@ $^ -no-pie -T linker.ld

all : vuln

clean:
	rm -f *.o vuln
