/*
 * Authors: 
 * Gutiérrez Gómez Yohan Leonardo
 * Hernández Alvarado Abraham Jesús
 * Huerta García Carlos
 * Ocaña Navarrete Marco Antonio
 * Zúñiga Rodriguez Diego
*/

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#define LINE_LEN 16

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include "ethernet.h"
#include "llc.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "igmp.h"
#include "tcp.h"
#include "udp.h"

pcap_t *adhandle;
unsigned int p = 0, ip = 0, arp = 0, rarp = 0, llc = 0, icmp = 0,
				igmp = 0, tcp = 0, udp = 0, nBytes = 0;

/* IGMP Analysis */
void igmpAnalysis(const u_char* igmp_pdu, u_char* index, unsigned int *igmp) {
    if((igmp_pdu[1] == 0 && igmp_pdu[0] != 23 && igmp_pdu[0] != 34 &&
		igmp_pdu[0] != 22) || igmp_pdu[0] == 18) { //IGMPv1
		printf("\nIGMP (Internet Group Management Protocol) v1");
		igmpv1_header* igmp_header = (igmpv1_header*)igmp_pdu;
		printf("\nVersion: %d", igmp_header->version_type&240);
		printf("\nType: %d", igmp_header->version_type&15);
		print_igmp_type(&igmp_header->version_type);
		printf("\nUnused: %d", igmp_header->unused);
		printf("\nChecksum: %x", igmp_header->cks);
		printf("\nGroup Address: %d.%d.%d.%d", igmp_header->group_addrss.a,
				igmp_header->group_addrss.b, igmp_header->group_addrss.c,
				igmp_header->group_addrss.d); //Group Address
		*index += sizeof(igmp_header);
	} else if((igmp_pdu[1] != 0 && igmp_pdu[0] != 18 && igmp_pdu[0] != 34) || 
				igmp_pdu[0] == 22) { //IGMPv2
		printf("\nIGMP (Internet Group Management Protocol) v2");
		igmpv2_header* igmp_header = (igmpv2_header*)igmp_pdu;
		printf("\nType: %d", igmp_header->type);
		print_igmp_type(&igmp_header->type);
		printf("\nMax Response Time: %x", igmp_header->mxrsptm);
		printf("\nChecksum: %x", igmp_header->cks);
		printf("\nGroup Address: %d.%d.%d.%d", igmp_header->group_addrss.a,
				igmp_header->group_addrss.b, igmp_header->group_addrss.c,
				igmp_header->group_addrss.d); //Group Address
		*index += sizeof(igmp_header);
	} else { //IGMPv3
		int i, k, n = 0;
		u_short ngrs = 0, j = 0, nsrcs = 0;
		printf("\nIGMP (Internet Group Management Protocol) v3");
		igmpv3_header* igmp_header = (igmpv3_header*)igmp_pdu;
		printf("\nType: 0x%x", igmp_header->type);
		print_igmp_type(&igmp_header->type);
		printf("\nReserved (1): %d", igmp_header->rsv1);
		printf("\nChecksum: %x", igmp_header->cks);
		printf("\nReserved (2): %d", igmp_header->rsv2);
		ngrs = igmp_pdu[6] * 256 + igmp_pdu[7];
		printf("\nNumber of group records: %hd", ngrs);
		*index += sizeof(igmp_header);
		n += sizeof(igmp_header);
		igmp_group_record* group_record;
		for(i = 0; i < ngrs; i++) {
			group_record = (igmp_group_record*)(igmp_pdu + n);
			printf("\nGroup Record [%d]:\n\tRecord Type: %d", i + 1, group_record->rtype);
			print_igmp_rtype(&group_record->rtype);
			printf("\n\tAuxiliar Data Length: %d", group_record->auxlen);
			nsrcs = igmp_pdu[n + 2]*256 + igmp_pdu[n + 3];
			printf("\n\tNumber of sources: %hd", nsrcs);
			printf("\n\tGroup Address: %d.%d.%d.%d", group_record->multicast_addrss.a,
					group_record->multicast_addrss.b, group_record->multicast_addrss.c,
					group_record->multicast_addrss.d); //Multicast Address
			ipv4_address* src_addresses = (ipv4_address*)(group_record + sizeof(igmp_group_record));
			for(j = 0; j < nsrcs; j++) printf("\n\t\tSource Address [%d]: %d.%d.%d.%d", j + 1,
												src_addresses[j].a, src_addresses[j].b,
												src_addresses[j].c, src_addresses[j].d);
			printf("\n\tAuxiliar Data:\n");
			n += sizeof(group_record) + j * sizeof(ipv4_address);
			*index += sizeof(group_record) + j * sizeof(ipv4_address);
			for(k = n; k < n + group_record->auxlen * 32; k++){
				printf("%x ",igmp_pdu[k]);
				if ((i % LINE_LEN) == 0 && i != 0) printf("\n");
			}											
			n += group_record->auxlen * 32;
			*index += group_record->auxlen * 32;
		}
	}
	++(*igmp);
}

/* ipv4 pdu analysis */
u_char ipv4Analysis (const u_char *ip_pdu, int *icmp, int *igmp, unsigned int *tcp, unsigned int *udp) {
	ipv4_header* ip_header = (ipv4_header*)ip_pdu;
	u_char ihl = (ip_header->version_ihl & 15) * 4, i;
	printf("\nIP (Internet Protocol)\nInternet Protocol Version: %d\nIHL (IP Header Length): %d",
	ip_header->version_ihl >> 4, ihl); //Version & IHL
	print_ipTos(&ip_header->tos);
	printf("\nTotal Length (Size of datagram, header + data): %d", ip_header->tlen);
	printf("\nIP Packet ID (Identification): %d", ip_header->identifier);
	printf("\nFlag (Unused): %d", ip_header->flags_fragmentOffest >> 15);
	printf("\nFlag (Don't fragment): %d", (ip_header->flags_fragmentOffest >> 14) & 1);
	printf("\nFlag (More): %d", (ip_header->flags_fragmentOffest >> 13) & 1);
	printf("\nFragment offset: %d", ip_header->flags_fragmentOffest & 8191);
	printf("\nTime to live (number of network hops): %d", ip_header->ttl);
	print_ipProtocol(&ip_header->protocol);
	printf("\nHeader checksum: %x", ip_header->cheksum); //Cheksum
	printf("\nSource IP Address: %d.%d.%d.%d", ip_header->source_address.a, ip_header->source_address.b,
	ip_header->source_address.c, ip_header->source_address.d); // Source IP Addr
	printf("\nDestination IP Address: %d.%d.%d.%d", ip_header->destination_address.a, ip_header->destination_address.b,
	ip_header->destination_address.c, ip_header->destination_address.d); //Destination IP Addr
	if(ihl > 20){ //Options & Padding
		printf("\nOptions & Padding:\n");
		for (i = 0; i < ihl - 20; i++) {
			printf("%.2x ", ip_header->options_padding[i]);
			if ((i % LINE_LEN) == 0 && i != 0) printf("\n");
		}
	}
	switch(ip_header->protocol) {
		case 1:
			icmpAnalysis((icmp_header*)(ip_pdu + ihl), &ihl, icmp);
			break;
		case 2:
			igmpAnalysis(ip_pdu + ihl, &ihl, igmp);
			break;
		case 6:
			tcpAnalysis((tcp_header*)(ip_pdu + ihl), &ihl, tcp);
			break;
		case 17:
			udpAnalysis((udp_header*)(ip_pdu + ihl), &ihl, udp);
			ihl += 2; //return position after transport protocol pdu
			break;
		default: break;
	}
	return ihl;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	char control, timestr[16];
	u_int i = 0;
	u_short length_or_type;
	struct tm *ltime;
	time_t local_tv_sec;
	/* save the packet on the dump file */
    if(dumpfile) pcap_dump(dumpfile, header, pkt_data);
	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
	/* print pkt timestamp and pkt len */
	printf("Packet timestamp: %s,%.6d\nLength: %d\n", timestr, header->ts.tv_usec, header->len);
	/* Packet Analysis */
    printf("\nDestination MAC Address: "); //Destination MAC Address
    for (i = 0; (i < 6) ; i++)  printf("%.2x ", pkt_data[i]);
    printf("\nSource MAC Address: "); //Source MAC Address
    for (i = 6; (i < 12) ; i++) printf("%.2x ", pkt_data[i]);
    length_or_type = pkt_data[i] * 256 + pkt_data[13];
	if(length_or_type < 1500){ //IEEE 802.3 LLC Analysis
		llc++;
		printf("\nPacket type: IEEE 802.3");
    	printf("\nLLC (Logic Link Control)\nData length: %d", length_or_type); //Data length
    	printf("\nDestination Service Access Point (DSAP): %.2x\n", pkt_data[14]); //DSAP
    	printf((pkt_data[14] & 1 ? "Group" : "Individual")); //Indiviual or Group
    	print_sap_protocol(&pkt_data[14]); //DSAP Protocol
		printf("\nSource Service Access Point (DSAP): %.2x\n", pkt_data[15]);
    	printf((pkt_data[15] & 1) ? "Response" : "Command"); //Command or Response
    	print_sap_protocol(&pkt_data[15]); //SSAP Protocol
		if(!(pkt_data[16] & 1)){
			printf("\nI packet");
    		if(length_or_type > 3){ //I Packet with length > 3
				printf("\nReceive sequence number: %d", (pkt_data[17] >> 1) & 127);
				printf("\nSend sequence number: %d", (pkt_data[16] >> 1) & 127);
				printf((pkt_data[17] & 1) ? "\nPoll bit P/F = 1" : "\nFinal bit P/F = 0");
				printf("\nData: \n");
			} else { //I Packet with length <= 3
				printf("\nReceive sequence number: %d", pkt_data[16] >> 5);
				printf("\nSend sequence number: %d", (pkt_data[16] >> 1) & 7);
				printf((pkt_data[16] & 16) ? "\nPoll bit P/F = 1" : "\nFinal bit P/F = 0");
				printf("\nData: \n%.2x ", pkt_data[17]);
			}
		} else
			if(!((pkt_data[16] >> 1) & 1)){
				printf("\nS packet"); 
				if(length_or_type > 3){ //S Packet with length > 3
					printf("\nReceive sequence number: %d", (pkt_data[17] >> 1) & 127);
					print_pkt_scode((u_short)((pkt_data[16] >> 2) & 3));
					printf((pkt_data[17] & 1) ? "\nPoll bit P/F = 1" : "\nFinal bit P/F = 0");
					printf("\nData: \n");
				} else { //S Packet with length <= 3
					printf("\nReceive sequence number: %d", pkt_data[16] >> 5);
					print_pkt_scode((u_short)((pkt_data[16] >> 2) & 3));
					printf((pkt_data[16] & 16) ? "\nPoll bit P/F = 1" : "\nFinal bit P/F = 0");
					printf("\nData: \n%.2x ", pkt_data[17]);
				}
			} else { //U Packet
				printf("\nU packet");
				print_pkt_umode(&pkt_data[16]);
				printf((pkt_data[16] & 16) ? "\nPoll bit P/F = 1" : "\nFinal bit P/F = 0");
				printf("\nData: \n%.2x ", pkt_data[17]);
			}
	    for (i = 18; i < (header->caplen - 4); i++) { //LLC PDU Data
			printf("%.2x ", pkt_data[i]);
			if ((i % LINE_LEN) == 0) printf("\n");
		}
		printf("\nCRC: ");
		for (i = header->len - 4; i < header->caplen; i++) printf("%.2x ", pkt_data[i]);
	} else {
		print_pkt_type(&length_or_type, &pkt_data[i], &pkt_data[13]);
		if(length_or_type == 2048) { // IP Protocol Analysis
			++ip;
			i += ipv4Analysis((pkt_data + 14), &icmp, &igmp, &tcp, &udp);
			printf("\nData: \n");
			for (i += 0; i < header->caplen; i++){
				printf("%.2x ", pkt_data[i]);
				if ((i % LINE_LEN) == 0) printf("\n");
			}
		} else if(length_or_type == 2054){     //Ethernet ARP Anyalisis
			++arp;
			print_hwType(&pkt_data[14], &pkt_data[15]);
			printf((pkt_data[16] * 255 + pkt_data[17]) == 2048 ? "\nProtocol type: Internet Protocol IP"
																: "\nProtocol Type: Unidentified");
			printf("\nARP (Address Resolution Protocol)");
			printf("\nHardware Address length  (MAC): %d", pkt_data[18]);
			printf("\nProtocol Address length: %d", pkt_data[19]);
			print_opCode(&pkt_data[20], &pkt_data[21], &arp, &rarp);
			printf("\nSender Hardware Address (MAC): "); //Sender Hardware Address
			for (i = 22; (i < 27) ; i++) printf("%.2x ", pkt_data[i]);
			printf("\nSender Protocol Address: %d.%d.%d.%d", pkt_data[28], pkt_data[29], pkt_data[30], pkt_data[31]);
			printf("\nTarget Hardware Address (MAC): "); //Target Hardware Address
			for (i = 32; (i < 37) ; i++) printf("%.2x ", pkt_data[i]);
			printf("\nTarget Protocol Address: %d.%d.%d.%d", pkt_data[38], pkt_data[39], pkt_data[40], pkt_data[41]);
		} else { //Ethernet Data
			printf("\nData: ");
			for (i += 2; i < (header->caplen - 4); i++){
				printf("%.2x ", pkt_data[i]);
				if ((i % LINE_LEN) == 0) printf("\n");
			}
			printf("\nCRC: ");
			for (i = header->len - 4; i < header->caplen; i++) printf("%.2x ", pkt_data[i]);
		}
		nBytes+=i;
	}
	// Continue analyzing or quit
    printf("\n\nGet the next packet (Y/N, y/n)?\n");
    fflush(stdin);
    scanf("%c", &control);
    if(control == 'N' || control == 'n') pcap_breakloop(adhandle);
	p++;
}

int main() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_dumper_t *dumpfile = NULL;
	int quantity;
	int inum;
	int i = 0;
	struct bpf_program filtercode;
	char promiscuous, save, errbuf[PCAP_ERRBUF_SIZE], filterstr[128], source[PCAP_BUF_SIZE], filepath[128], dumpfilepath[128];
	u_int netmask;
	/* Title */
	printf("\nNetwork Protocol Analyzer using pcap library for Windows by:");
	/* Authors */
	printf("\nGutiérrez Gómez Yohan Leonardo\nHernández Alvarado Abraham Jesús\nHuerta García Carlos\nOcaña Navarrete Marco Antonio\nZúñiga Rodriguez Diego\n\nWelcome:\n");
	/* Ask if the capture will be done from a network interface or a file */
	printf("\nCapture packets from:\n0. Network interface device\n1. A file from given path\nEnter the option number (0/1): ");
	scanf("%hd", &inum);
	printf("\nCapture packets with promiscuous mode? (y/n): ");
	fflush(stdin);
	scanf("%c", &promiscuous);
	if(promiscuous == 'Y' || promiscuous == 'y') promiscuous = PCAP_OPENFLAG_PROMISCUOUS;
	else promiscuous = 0;
	if(inum) {
		/* Get the file path */
		printf("\nEnter the file path for packet capturing: ");
		fflush(stdin);
		scanf("%s", filepath);
		/* Create the source string according to the new WinPcap syntax */
		if(pcap_createsrcstr(source,         // variable that will keep the source string
								PCAP_SRC_FILE,  // we want to open a file
								NULL,           // remote host
								NULL,           // port on the remote host
								filepath,       // name of the file we want to open
								errbuf          // error buffer
									)) {
			fprintf(stderr,"\nError creating a source string\n");
			return -1;
		}
		/* Open the capture file */
		if(!(adhandle = (pcap_t *)pcap_open(source,	// name of the device
							65536,	// portion of the packet to capture
									// 65536 guarantees that the whole packet will be captured on all the link layers
							promiscuous,	// promiscuous mode
							1000,	// read timeout
							NULL,	// authentication on the remote machine
							errbuf	// error buffer
								))) {
			fprintf(stderr,"\nUnable to open the file %s\n", source);
			return -1;
		}
		pcap_loop(adhandle, 0, packet_handler, NULL);
	} else {
		/* Retrieve the device list */
		if(pcap_findalldevs(&alldevs, errbuf) == -1) {
			fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}
		/* Print the list */
		for(d=alldevs; d; d=d->next) {
			printf("%d. %s", ++i, d->name);
			(d->description) ? printf(" (%s)\n", d->description): printf(" (No description available)\n");
		}
		if(i == 0) {
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}
		printf("Enter the interface number (1-%d): ", i);
		scanf("%d", &inum);
		if(inum < 1 || inum > i) {
			printf("\nInterface number out of range.\n");
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}
		/* Jump to the selected adapter */
		for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
		/* Open the device */
		/* Open the adapter */
		if (!(adhandle = pcap_open_live(d->name,	// name of the device
								65536,			// portion of the packet to capture. 
												// 65536 grants that the whole packet will be captured on all the MACs.
								promiscuous,		// promiscuous mode (nonzero means promiscuous)
								1000,			// read timeout
								errbuf			// error buffer
									))) {
			fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}
		i = 0;
		do{
			/* tcpdump filter */
			printf("\ntcpdump syntax reference: https://www.tcpdump.org/manpages/pcap-filter.7.html\nEnter the filter string for packet capturing or 'no' (use tcpdump syntax):\n");
			fflush(stdin);
			scanf("%s", filterstr);
			if(strcmp("no", filterstr)) {
				/* Compile the filter */
				if(pcap_compile(adhandle, &filtercode, filterstr, 1, PCAP_NETMASK_UNKNOWN) < 0){
					i = 1;
					fprintf(stderr, "\nError compiling into a filter program\n");
					continue;
				}
				/* Set the filter */
				if(pcap_setfilter(adhandle, &filtercode) < 0){
					i = 1;
					fprintf(stderr, "\nError setting the filter\n");
					continue;
				}
			}
			/* Ask how many packets will be captured */
			printf("\n-1 or 0 value causes all the packets received in one buffer to be processed when reading a live capture,\nand causes all the packets in the file to be processed when reading a file\nEnter how many packets will be captured: ");
			scanf("%d", &quantity);
			/* Ask if the packet capture will be saved */
			printf("\nSave packet capture? (y/n): ");
			fflush(stdin);
			scanf("%c", &save);
			if (save == 'Y' || save == 'y'){
				/* Get the file path */
				printf("\nEnter the file path for packet capture saaving (.pcap):\n");
				fflush(stdin);
				scanf("%s", dumpfilepath);
				/* Open the dump file */
				if(!(dumpfile = pcap_dump_open(adhandle, dumpfilepath))){
					fprintf(stderr,"\nError opening output file\n");
					return -1;
				}
			}
			printf("\nListening on %s...\n", d->description);
			/* At this point, we don't need any more the device list. Free it */
			pcap_freealldevs(alldevs);
			/* start the capture without end */
			pcap_loop(adhandle, quantity, packet_handler, (unsigned char *)dumpfile);
		} while (i);
	}
	pcap_close(adhandle);
	// Print stats
	printf("\nStats:\nPackets captured: %d\nBytes captured: %d\nLLC packets: %d\nIP packets: %d\nARP packets: %d\nRARP packets: %d\nICMP packets: %d\nIGMP packets: %d\nTCP packets: %d\nUDP packets: %d\n",
			p, nBytes, llc, ip, arp, rarp, icmp, igmp, tcp, udp);
	return 0;
}

