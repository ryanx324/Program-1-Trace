#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>

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
        char opcode[2]; // Opcode
        unsigned char hard_type[2]; // Hard type
        unsigned char prot_type[2]; // Prot type
        unsigned char hard_size[1]; // Hard size
        unsigned char prot_size[1]; // Prot size
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

        // Reading the ARP header
        struct arp_header *arp_hdr = (struct arp_header*) packet;

        //ETH Header
        char dest_MAC_addr[18];
        char src_MAC_addr[18];

        //ARP Header
        char opcode[2];
        char senderMAC[18];
        char senderIP[14];
        char targetMAC[18];
        char targetIP[14];

        // Reading the Eth Header
        memcpy(dest_MAC_addr, ether_ntoa((struct ether_addr*)&eth_hdr->dest_addr), sizeof(dest_MAC_addr));
        memcpy(src_MAC_addr, ether_ntoa((struct ether_addr*)&eth_hdr->source_addr), sizeof(src_MAC_addr));

        printf("Packet Number: %d  Frame Len: %d\n\n", packet_num, header->len); // Print packet num and frame len

        printf("\tEthernet Header\n"); // Print Eth header

        printf("\t\tDest MAC: %s\n", dest_MAC_addr);
        printf("\t\tSource MAC: %s\n", src_MAC_addr);
        printf("\t\tType: ");

        //Case statement for the different types
        unsigned short e_type = ntohs(eth_hdr->type);
        switch(e_type){
            case 0x0806: // ARP in hexadecimal
            printf("ARP\n");
            break;

            default:
            printf("%04x\n", e_type);
        }

        printf("\n");
        printf("\tARP Header\n"); //Print ARP header

        // Reading the ARP Header
        memcpy(opcode, inet_ntoa(*(struct in_addr*)&arp_hdr->opcode), sizeof(opcode));
        memcpy(senderMAC, inet_ntoa(*(struct in_addr*)&arp_hdr->senderMAC), sizeof(senderMAC));
        memcpy(senderIP, inet_ntoa(*(struct in_addr*)&arp_hdr->senderIP), sizeof(senderIP));
        memcpy(targetMAC, inet_ntoa(*(struct in_addr*)&arp_hdr->targetMAC), sizeof(targetMAC));
        memcpy(targetIP, inet_ntoa(*(struct in_addr*)&arp_hdr->targetIP), sizeof(targetIP));


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

