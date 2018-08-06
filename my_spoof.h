#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#define ETHERTYPE_IP		0x0800		/* IP protocol */
#define ETHERTYPE_ARP	0x0806		/* Addr. resolution protocol */

void usage();
void findMyMac(char* dev,unsigned char *my_mac);
void printMyMac(unsigned  char *my_mac);
u_char* getYourMac(char *dev, in_addr *src_ip, in_addr *dst_ip, unsigned char *src_mac);
void arpInfect(char *dev, in_addr *src_ip, in_addr *dst_ip, unsigned char *src_mac, unsigned char *dst_mac);