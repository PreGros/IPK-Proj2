PRJ=Sniffer
PROGS=sniffer.cpp
CC=g++
CFLAGS=-std=c++11 -Wall -Wextra -Werror -pedantic

$(PRJ): $(PROGS)
	$(CC) $(CFLAGS) $(PROGS) -g -o $(PRJ) -lpcap

clean: 
	rm -f $(PRJ)
	