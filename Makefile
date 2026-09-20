CC = gcc
CXX = g++
CFLAGS = -fno-stack-protector -no-pie -z norelro -g
LDFLAGS = -ldl

all: b0f_large exploit

b0f_large: b0f_large.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

auto_offsets.o: auto_offsets.c auto_offsets.h
	$(CC) -c -o $@ auto_offsets.c $(LDFLAGS)

exploit: exploit.cpp auto_offsets.o auto_offsets.h
	$(CXX) -std=c++11 -o $@ exploit.cpp auto_offsets.o $(LDFLAGS)

clean:
	rm -f b0f_large exploit auto_offsets.o

.PHONY: all clean
