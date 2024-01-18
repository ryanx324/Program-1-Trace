#include <stdio.h>
#include <pcap.h>
#include <string.h>

int main(int argc, char *argv[]){
    if (argc != 2){
        fprintf(stderr, "Error: Not the correct amount of args\n"); // Error if there is an incorrect amount of arguments
        return 1;
    }

    char ERRBUF[PCAP_ERRBUF_SIZE]; // Error buffer of size defined by "pcap.h" (256)

    pcap_t *packet_handler = pcap_open_offline(argv[1], ERRBUF);
    if (packet_handler == NULL){
        fprintf(stderr, "Failed to open file %s: %s\n", argv[1], ERRBUF); // Error if file is unable to open
        return 2;
    }

    // READING THE PACKET
    struct pcap_pkthdr *header; // Points to the header of the packet
    const unsigned char *packet; // Points to the data of the packet
    int output; // Success or Failure
    int packet_num; // Packet Number

    // Struct for Ethernet Header
    struct ethernet_header {
        unsigned char dest_addr[6]; // Destination MAC Address
        unsigned char source_addr[6]; // Source MAC Address
        unsigned short type; // Type
    };

    // Struct for ARP Header
    struct arp_header {
        char opcode; // Opcode
        unsigned char senderMAC[6]; // Sender MAC address
        unsigned char senderIP[4]; // Sender IP address
        unsigned char targetMAC[6]; // Target MAC address
        unsigned char targetIP[4]; // Target IP address
    };
    
    // Reading the packet file
    while ((output = pcap_next_ex(packet_handler, &header, &packet)) == 1){
        packet_num++;
         
        // Reading the ethernet header
        struct ethernet_header *eth_hdr = (struct ethernet_header*) packet;

        printf("Packet Number: %d  Frame Len: %d\n", packet_num, header->len); // Print packet num and frame len

        printf("\n");

        printf("\tEthernet Header\n"); // Print Eth header

        printf("\t\tDest MAC: "); 
        for (int i = 0; i < 6; i++){
            printf("%02x", eth_hdr->dest_addr[i]); // Print Dest MAC addr
            if (i < 6 - 1){
                printf(":");
            }
        }

        printf("\n");

        printf("\t\tSource MAC: ");
        for (int i = 0; i < 6; i++){
            printf("%02x", eth_hdr->source_addr[i]); // Print Source MAC addr
            if (i < 6 - 1){
                printf(":");
            }
        }
        
        printf("\n");
        printf("\t\tType: ");

        //Case statement for the different types
        unsigned short e_type = ntohs(eth_hdr->type);
        switch(e_type){
            case 0x0806: // ARP in hexadecimal
            printf("ARP\n");

            // default:
            // printf("%04x\n", eth_hdr->type);
        }

        printf("\n");
        printf("\t ARP Header\n");

        printf("\t\tSender MAC: ");

        if (output == -1){
            fprintf(stderr, "Packet read error\n");
            break;
        }

        if (output == -2){
            fprintf(stderr, "Error: EOF\n");
        }

    }

    pcap_close(packet_handler); // Close the packet
    return 0;
}

