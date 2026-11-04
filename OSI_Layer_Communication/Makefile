CC      = gcc
CFLAGS  = -std=gnu11 -O2 -Wall -Wextra

all: client server

client: client.o layers.o net.o
	$(CC) $^ -o $@

server: server.o layers.o net.o
	$(CC) $^ -o $@

%.o: %.c layers.h net.h
	$(CC) $(CFLAGS) -c $< -o $@

run: all
	python3 osi_ui.py -m "Hello OSI Model"

test: all
	python3 osi_ui.py -m "Hello OSI Model" --delay 0 --no-color
	python3 osi_ui.py -m "tampered frame" --corrupt --delay 0 --no-color

clean:
	rm -f *.o client server

.PHONY: all run test clean
