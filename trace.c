#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "checksum.h"

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
    uint8_t version_and_headerlen;
    uint8_t service_type;
    uint16_t total_len;
    uint16_t indentification;
    uint16_t flag_and_fragoffset;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t header_checksum;
    unsigned char src_IP[4];
    unsigned char dest_IP[4];
};

//Struct for TCP Header
struct tcp_header{
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t headerlen_and_reservedbits;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
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

    // BIG STRING
    char IP_filler_string[1000];
    
    // Reading the packet file
    while ((output = pcap_next_ex(packet_handler, &header, &packet)) == 1){
        packet_num++;
         
        // Reading the ethernet header
        struct ethernet_header *eth_hdr = (struct ethernet_header*) packet;

        //ETH Header byte len
        char dest_MAC_addr[20];
        char src_MAC_addr[18];

        //ARP Header byte len
        unsigned short opcode;
        char senderMAC[18];
        char senderIP[14];
        char targetMAC[18];
        char targetIP[14];

        //IP Header byte len
        char header_length[2];
        char TOS[4];
        char TTL[4];
        char IP_PDU_Len[4];
        char protocol[4];
        char checksum[5]; 
        char sender_IP[18];
        char dest_IP[18];

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
                // Reading the ARP header
                struct arp_header *arp_hdr = (struct arp_header*) (packet + sizeof(struct ethernet_header));

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
                // Reading the IP header
                struct ip_header *ip_hdr = (struct ip_header*) (packet + sizeof(struct ethernet_header));

                printf("IP\n\n");
                printf("\tIP Header\n");
                int header_length = (ip_hdr->version_and_headerlen & 0x0F) * 4;

                
                printf("\t\tHeader Len: %d (bytes)\n", header_length);
                printf("\t\tTOS: 0x%x\n", ip_hdr->service_type);
                printf("\t\tTTL: %d\n", ip_hdr->TTL);
                unsigned short ip_pdu_len = ntohs(ip_hdr->total_len);
                printf("\t\tIP PDU Len: %d (bytes)\n", ip_pdu_len);
                printf("\t\tProtocol: ");
                switch(ip_hdr->protocol){
                    case 6:
                    printf("TCP\n");
                    struct tcp_header *tcp_hdr = (struct tcp_header*) ((unsigned char*)ip_hdr + header_length);
                    // sprintf(IP_filler_string, "\tTCP Header\n\t\tSource Port: %d\n\t\tDest Port: %d\n\t\tSequence Number: %d\n\t\tACK Number: %d\n\t\tACK Flag: %d\n\t\tSYN Flag: %d\n\t\tRST Flag: %d\n\t\tFIN Flag: %d\n\t\tWindow Size: %d\n\t\tChecksum: %d\n");
                    sprintf(IP_filler_string, "\tTCP Header\n\t\tSource Port: ");
                    if (ntohs(tcp_hdr->source_port) == 80){
                        sprintf(IP_filler_string,"%sHTTP\n\t\tDest Port: : %d\n\t\t",IP_filler_string, ntohs(tcp_hdr->dest_port));
                    }
                    else if (ntohs(tcp_hdr->dest_port) == 80){
                        sprintf(IP_filler_string,"%s: %d\n\t\tDest Port: HTTP\n\t\t",IP_filler_string, ntohs(tcp_hdr->source_port));
                    }

                    break;

                    case 1:
                    printf("ICMP\n");
                    break;

                    case 17:
                    printf("UDP\n");\
                    break;

                    default:
                    fprintf(stderr, "ERROR\n");
                    break;
                }
                printf("\t\tChecksum: GO BACK TO THIS\n");
                
                char IP_sender_addr[14];
                char IP_dest_addr[14];

                memcpy(IP_sender_addr, inet_ntoa(*(struct in_addr*)&ip_hdr->src_IP), sizeof(IP_sender_addr));
                memcpy(IP_dest_addr, inet_ntoa(*(struct in_addr*)&ip_hdr->dest_IP), sizeof(IP_dest_addr));

                printf("\t\tSender IP: %s\n", IP_sender_addr);
                printf("\t\tDest IP: %s\n\n%s", IP_dest_addr, IP_filler_string);
                ////////////////////////////////////////////
                break;

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

