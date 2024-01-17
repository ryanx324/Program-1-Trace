#include <stdio.h>
#include <pcap.h>
#include <string.h>

int main(int argc, char *argv[]){
    if (argc != 2){
        fprintf(stderr, "Error: Not the correct amount of args\n", argv[0]); // Error if there is an incorrect amount of arguments
        return 1;
    }

    char ERRBUF[PCAP_ERRBUF_SIZE]; // Error buffer of size defined by "pcap.h" (256)

    pcap_t *packet_handler = pcap_open_offline(argv[1], ERRBUF);
    if (packet_handler == NULL){
        fprintf(stderr, "Failed to open file %s: %s\n", argv[1], ERRBUF); // Error if file is unable to open
        return 2;
    }

    //READING THE PACKET
    struct packet_header *header; // Points to the header of the packet
    const unsigned char *packet; //Points to the data of the packet
    int output; // Success or Failure

    



    pcap_close(packet_handler); // Close the packet
    return 0;
}

