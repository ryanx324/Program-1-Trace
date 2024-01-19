#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>

// READING THE PACKET
struct pcap_pkthdr *header; // Points to the header of the packet
const unsigned char *packet; // Points to the data of the packet
int output; // Success or Failure
int packet_num = 0; // Packet Number

// Struct for Ethernet Header
struct ethernet_header {
    unsigned char dest_addr[6]; // Destination MAC Address
    unsigned char source_addr[6]; // Source MAC Address
    unsigned short type; // Type
};

// Struct for ARP Header
struct arp_header {
    unsigned char hard_type[2]; // Hard type
    unsigned char prot_type[2]; // Prot type
    unsigned char hard_size[1]; // Hard size
    unsigned char prot_size[1]; // Prot size
    short opcode; // Opcode 
    unsigned char senderMAC[6]; // Sender MAC address
    unsigned char senderIP[4]; // Sender IP address
    unsigned char targetMAC[6]; // Target MAC address
    unsigned char targetIP[4]; // Target IP address
};

// Struct for IP Header
struct ip_header{
    unsigned char version_and_headerlen[1];
    unsigned char service_type[1];
    unsigned char total_len[2];
    unsigned char indentification[2];
    unsigned char flag_and_fragoffset[2];
    unsigned char TTL[1];
    unsigned char protocol[1];
    unsigned char header_checksum[2];
    unsigned char src_IP[4];
    unsigned char dest_IP[4];
};

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
    
    // Reading the packet file
    while ((output = pcap_next_ex(packet_handler, &header, &packet)) == 1){
        packet_num++;
         
        // Reading the ethernet header
        struct ethernet_header *eth_hdr = (struct ethernet_header*) packet;

        // Reading the ARP header
        struct arp_header *arp_hdr = (struct arp_header*) (packet + sizeof(struct ethernet_header));

        //ETH Header byte len
        char dest_MAC_addr[20];
        char src_MAC_addr[18];

        //ARP Header byte len
        unsigned short opcode;
        char senderMAC[18];
        char senderIP[14];
        char targetMAC[18];
        char targetIP[14];

        // Reading the Eth Header
        memcpy(dest_MAC_addr, ether_ntoa((struct ether_addr*)&eth_hdr->dest_addr), sizeof(dest_MAC_addr));
        memcpy(src_MAC_addr, ether_ntoa((struct ether_addr*)&eth_hdr->source_addr), sizeof(src_MAC_addr));

        // Print packet num and frame len
        printf("Packet Number: %d  Frame Len: %d\n\n", packet_num, header->len); 

        // Print Ethernet header
        printf("\tEthernet Header\n"); 
        printf("\t\tDest MAC: %s\n", dest_MAC_addr);
        printf("\t\tSource MAC: %s\n", src_MAC_addr);
        printf("\t\tType: ");

        //Case statement for the different types
        unsigned short e_type = ntohs(eth_hdr->type);
        switch(e_type){
            case 0x0806: // ARP in hexadecimal

                // Reading the ARP Header
                printf("ARP\n\n");
                printf("\tARP header\n"); 

                opcode = ntohs(arp_hdr->opcode);
                memcpy(senderMAC, ether_ntoa((struct ether_addr*)&arp_hdr->senderMAC), sizeof(senderMAC));
                memcpy(senderIP, inet_ntoa(*(struct in_addr*)&arp_hdr->senderIP), sizeof(senderIP));
                memcpy(targetMAC, ether_ntoa((struct ether_addr*)&arp_hdr->targetMAC), sizeof(targetMAC));
                memcpy(targetIP, inet_ntoa(*(struct in_addr*)&arp_hdr->targetIP), sizeof(targetIP));

                printf("\t\tOpcode: ");

                if (opcode == 1){
                    printf("Request\n");
                }
                else if (opcode == 2){
                    printf("Reply\n");
                }
                else{
                    printf("%d\n", opcode);
                }

                printf("\t\tSender MAC: %s\n", senderMAC);
                printf("\t\tSender IP: %s\n", inet_ntoa(*(struct in_addr*)&arp_hdr->senderIP));
                printf("\t\tTarget MAC: %s\n", targetMAC);
                printf("\t\tTarget IP: %s\n\n", inet_ntoa(*(struct in_addr*)&arp_hdr->targetIP));
                break;

            case 0x0800: // IP Header

            default:
            printf("%04x\n", e_type);
        }


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

