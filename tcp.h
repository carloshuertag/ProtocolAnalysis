/*TCP Header*/
typedef struct tcp_header {
	u_short srcport;
	u_short dstport; 
	u_int sqncn;
	u_int ackn;
	u_char dtoffs_rsv;
	u_char flags;
	u_short wndwsize;
	u_short cks;
	u_short urgntptr;
	u_int opts_pdng;
} tcp_header;

void tcpFlagsAnalysis(u_char *tcp_flags) {
	printf("\nTCP Flags:\nCWR Congesrion Window Reduced: %hd", (*tcp_flags >> 7) & 1);
	printf("\nECE ECN (Explicit Congestion Notification) - Echo: %hd",
			(*tcp_flags >> 6) & 1);
	printf("\nURG Urgent Pointer field significant: %hd", (*tcp_flags >> 5) & 1);
	printf("\nACK Acknowledge field significant: %hd", (*tcp_flags >> 4) & 1);
	printf("\nPSH Push Function: %hd", (*tcp_flags >> 3) & 1);
	printf("\nRST Reset the connection: %hd", (*tcp_flags >> 2) & 1);
	printf("\nSYN Synchronize sequence numbers: %hd", (*tcp_flags >> 1) & 1);
	printf("\nFIN No more data from sender: %hd", (*tcp_flags) & 1);
}

void tcpOptionsAnalysis(u_int *tcp_opts_pdng) {
	switch((*tcp_opts_pdng)&0xf000){
		case 0:
			printf("\nOption-Kind = 0: End of option list\nPadding: 00 00 00");
			break;
		case 1:
			printf("\nOption-Kind = 1: No-Operation\nPadding: 00 00 00");
			break;
		case 2:
			printf("\nOption-Kind = 2\nOption-Length: %d\nMaximum Segment Size: %d",
					(*tcp_opts_pdng >> 16) & 0x0f, (*tcp_opts_pdng) & 0x00ff);
			break;
		default:
			printf("\nOptions and Padding: %x", (*tcp_opts_pdng));
			break;
	}
}

void tcpAnalysis(tcp_header *tcp_h, u_char *index, unsigned int* tcp) {
	++(*tcp);
	*index += sizeof(tcp_header);
	printf("\nTCP");
	printf("\nSource Port: %d", tcp_h->srcport);
	printf("\nDestination Port: %d", tcp_h->dstport);
	printf("\nSequence Number: %d", tcp_h->sqncn);
	printf("\nAcknowledgment Number: %d", tcp_h->ackn);
	printf("\nData Offset: %d (32 bit words)", tcp_h->dtoffs_rsv & 240);
	printf("\nReserved: %x", tcp_h->dtoffs_rsv & 15);
	tcpFlagsAnalysis(&tcp_h->flags);
	printf("\nWindow Size: %d", tcp_h->wndwsize);
	printf("\nChecksum: %x", tcp_h->cks);
	printf("\nUrgent Pointer: %x", tcp_h->urgntptr);
	tcpOptionsAnalysis(&tcp_h->opts_pdng);
}

