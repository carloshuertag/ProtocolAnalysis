/* UDP Header */
typedef struct udp_header {
	u_short srcport;
	u_short dstport;
	u_short len;
	u_short cks;
} udp_header;

/* UDP Analysis */
void udpAnalysis(udp_header *udp_h, u_char *index, unsigned int *udp) {
	printf("\nUDP (User Datagram Protocol)");
	printf("\nSource Port: %d", udp_h->srcport);
	printf("\nDestination Port: %d", udp_h->dstport);
	printf("\nLength: %d", udp_h->len);
	printf("\nChecksum: %x", udp_h->cks);
	++(*udp);
	*index += sizeof(udp_header);
}

