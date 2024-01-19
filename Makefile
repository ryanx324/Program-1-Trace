# Example makefile for CPE464 Trace program
#
# Just links in pcap library

CC = gcc
LIBS = -lpcap
CFLAGS = -g -Wall -pedantic 
#CGLAGS = 

all:  trace

trace: trace.c 
	$(CC) $(CFLAGS) -o $@ trace.c $(LIBS)

clean:
	rm -f trace
