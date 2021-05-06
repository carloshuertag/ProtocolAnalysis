#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#define LINE_LEN 16

#include "protocols.h"

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	char control;
	u_int i = 0;
	u_short length_or_type;
	/*
	 * unused parameters
	 */
	(void)(param);
	(void)(pkt_data);
	/* print pkt timestamp and pkt len */
    printf("Packet timestamp and length: %ld:%ld (%ld)\n", header->ts.tv_sec,
															header->ts.tv_usec,
															header->len);
	/* Packet Analysis */
    printf("Destination MAC Address: "); //Destination MAC Address
    for (i = 0; (i < 6) ; i++)
        printf("%.2x ", pkt_data[i]);
    printf("\nSource MAC Address: "); //Source MAC Address
    for (i = 6; (i < 12) ; i++)
        printf("%.2x ", pkt_data[i]);
    length_or_type = pkt_data[i] * 256 + pkt_data[13];
	if(length_or_type < 1500){ //IEEE 802.3 LLC Analysis
		printf("\nPacket type: IEEE 802.3");
    	printf("\nLLC PDU\nData length: %d", length_or_type); //Data length
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
		}
		else
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
	    for (i = header->len - 4; i < header->caplen; i++)
	        printf("%.2x ", pkt_data[i]);
	} else { //Ethernet
		print_pkt_type(&length_or_type, &pkt_data[i], &pkt_data[13]);
		if(length_or_type == 2048) { // IP Protocol Analysis
			i += ipv4Analysis((ipv4_header*)(pkt_data + 14));
			printf("\nData: \n");
			for (i += 2; i < (header->caplen - 4); i++){
				printf("%.2x ", pkt_data[i]);
				if ((i % LINE_LEN) == 0) printf("\n");
			}
			printf("\nCRC: ");
			for (i = header->len - 4; i < header->caplen; i++)
				printf("%.2x ", pkt_data[i]);
		} else if(length_or_type == 2054){     //Ethernet ARP Anyalisis
				print_hwType(&pkt_data[14], &pkt_data[15]);
				printf((pkt_data[16] * 255 + pkt_data[17]) == 2048 ? "\nProtocol type: Internet Protocol IP"
																	: "\nProtocol Type: Unidentified");
				printf("\nHardware Address length  (MAC): %d", pkt_data[18]);
				printf("\nProtocol Address length: %d", pkt_data[19]);
				print_opCode(&pkt_data[20], &pkt_data[21]);
				printf("\nSender Hardware Address (MAC): "); //Sender Hardware Address
				for (i = 22; (i < 27) ; i++)
					printf("%.2x ", pkt_data[i]);
				printf("\nSender Protocol Address: %d.%d.%d.%d", pkt_data[28], pkt_data[29], pkt_data[30], pkt_data[31]);
				printf("\nTarget Hardware Address (MAC): "); //Target Hardware Address
				for (i = 32; (i < 37) ; i++)
					printf("%.2x ", pkt_data[i]);
				printf("\nTarget Protocol Address: %d.%d.%d.%d", pkt_data[38], pkt_data[39], pkt_data[40], pkt_data[41]);
				printf("\nData: ");
				for (i = 42; i < (header->caplen - 4); i++){
					printf("%.2x ", pkt_data[i]);
					if ((i % LINE_LEN) == 0) printf("\n");
				}
			} else { //Ethernet Data
				printf("\nData: ");
				for (i += 2; i < (header->caplen - 4); i++){
					printf("%.2x ", pkt_data[i]);
					if ((i % LINE_LEN) == 0) printf("\n");
				}
				printf("\nCRC: ");
				for (i = header->len - 4; i < header->caplen; i++)
					printf("%.2x ", pkt_data[i]);
			}
	}
	// Continue analyzing or quit
    printf("\n\nKeep listerning (Y/N, y/n)?\n");
    fflush(stdin);
    scanf("%c", &control);
    if(control == 'N' || control == 'n') exit(0);
}

int main() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	struct bpf_program filtercode;
	char errbuf[PCAP_ERRBUF_SIZE], filterstr[128], source[PCAP_BUF_SIZE], filepath[128];
	u_int netmask;
	/* Ask if the capture will be done from a network interface or a file */
	printf("\nCapture packets from:\n0. Network interface device\n1. A file from given path\nEnter the option number (0/1): ");
	scanf("%d", &inum);
	if(inum) {
		/* Get the file path */
		printf("\nEnter the file path for packet capturing:\n");
		fflush(stdin);
		scanf("%s", filepath);
		/* Create the source string according to the new WinPcap syntax */
		if(pcap_createsrcstr(source,         // variable that will keep the source string
								PCAP_SRC_FILE,  // we want to open a file
								NULL,           // remote host
								NULL,           // port on the remote host
								filepath,       // name of the file we want to open
								errbuf          // error buffer
									) != 0) {
			fprintf(stderr,"\nError creating a source string\n");
			return -1;
		}
		/* Open the capture file */
		if((adhandle = (pcap_t *)pcap_open(source,	// name of the device
							65536,	// portion of the packet to capture
									// 65536 guarantees that the whole packet will be captured on all the link layers
							PCAP_OPENFLAG_PROMISCUOUS,	// promiscuous mode
							1000,	// read timeout
							NULL,	// authentication on the remote machine
							errbuf	// error buffer
								)) == NULL) {
			fprintf(stderr,"\nUnable to open the file %s\n", source);
			return -1;
		}
		inum = 2147483647;
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
		printf("Enter the interface number (1-%d):", i);
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
		if ((adhandle = pcap_open_live(d->name,	// name of the device
								65536,			// portion of the packet to capture. 
												// 65536 grants that the whole packet will be captured on all the MACs.
								PCAP_OPENFLAG_PROMISCUOUS,		// promiscuous mode (nonzero means promiscuous)
								1000,			// read timeout
								errbuf			// error buffer
									)) == NULL) {
			fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}
	}
	i = 0;
	do{
		/* tcpdump filter */
		printf("\ntcpdump syntax reference: https://www.tcpdump.org/manpages/pcap-filter.7.html\nEnter the filter string for packet capturing (use tcpdump syntax):\n");
		fflush(stdin);
		scanf("%s", filterstr);
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
		printf("\nlistening on %s...\n", d->description);
		/* At this point, we don't need any more the device list. Free it */
		pcap_freealldevs(alldevs);
		/* start the capture without end */
		(inum == 2147483647) ? pcap_loop(adhandle, 0, packet_handler, NULL):
		pcap_loop(adhandle, -1, packet_handler, NULL);
	} while (i);
	pcap_close(adhandle);
	return 0;
}

