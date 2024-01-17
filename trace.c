#include <stdio.h>
#include <pcap.h>
#include <string.h>

int main(int argc, char *argv[]){
    if (argc != 2){
        fprintf(stderr, "Error: Not the correct amount of args\n", argv[0]); // Error if there is an incorrect amount of arguments
        return 1;
    }

    char ERRBUF[PCAP_ERRBUF_SIZE]; // Error buffer of size defined by the header

    pcap_t *handle_packet = pcap_open_offline(argv[1], ERRBUF);
    if (handle_packet == NULL){
        fprintf(stderr, "Failed to open file %s: %s\n", argv[1], ERRBUF); // Error if file is unable to open
        return 2;
    }

    return 0;
}

