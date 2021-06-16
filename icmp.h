/*ICMP Header*/
typedef struct icmp_header {
	u_char type;
	u_char code; 
	u_short cks;
} icmp_header;

void print_icmp_desc(u_char *type, u_char *code) {
	switch(*type) {
		case 0:
			printf("\nICMP Type: %d\nICMP Code: %d\nEcho Reply", *type, *code);
			break;
		case 3:
			switch(*code) {
				case 0:
					printf("\nICMP Type: %d\nICMP Code: %d\nDestination Network Unreachable", *type, *code);
					break;
				case 1:
					printf("\nICMP Type: %d\nICMP Code: %d\nDestination Host Unreachable", *type, *code);
					break;
				case 2:
					printf("\nICMP Type: %d\nICMP Code: %d\nDestination Protocol Unreachable", *type, *code);
					break;
				case 3:
					printf("\nICMP Type: %d\nICMP Code: %d\nDestination Port Unreachable", *type, *code);
					break;
				case 4:
					printf("\nICMP Type: %d\nICMP Code: %d\nFragmentation Needed and DF Flag Set", *type, *code);
					break;
				case 5:
					printf("\nICMP Type: %d\nICMP Code: %d\nSource Route Failed", *type, *code);
					break;
				default:
					printf("\nICMP Type: %d\nICMP Code: %d\nDestination Unreachable", *type, *code);
					break;
			}
			break;
		case 5:
			switch(*code) {
				case 0:
					printf("\nICMP Type: %d\nICMP Code: %d\nRedirect Datagram for the Network", *type, *code);
					break;
				case 1:
					printf("\nICMP Type: %d\nICMP Code: %d\nRedirect Datagram for the Host", *type, *code);
					break;
				case 2:
					printf("\nICMP Type: %d\nICMP Code: %d\nRedirect Datagram for the Type of Service and Network",
							*type, *code);
					break;
				case 3:
					printf("\nICMP Type: %d\nICMP Code: %d\nRedirect Datagram for the Service and Host", *type, *code);
					break;
				default:
					printf("\nICMP Type: %d\nICMP Code: %d\nRedirect Message", *type, *code);
					break;
			}
			break;
		case 8:
			printf("\nICMP Type: %d\nICMP Code: %d\nEcho Request", *type, *code);
			break;
		case 9:
			if(*code == 0) printf("\nICMP Type: %d\nICMP Code: %d\nRouter Advertisement\nUse to Discover Addresses of Operational Routers.",
									*type, *code);
			else printf("\nICMP Type: %d\nICMP Code: %d\nRouter Advertisement", *type, *code);
			break;
		case 10:
			if(*code == 0) printf("\nICMP Type: %d\nICMP Code: %d\nRouter Solicitation\nUse to Discover Addresses of Operational Routers.",
									*type, *code);
			else printf("\nICMP Type: %d\nICMP Code: %d\nRouter Solicitation", *type, *code);
			break;
		case 11:
			if(*code == 0) printf("\nICMP Type: %d\nICMP Code: %d\nTime to Live Exceeded in Transit",
									*type, *code);
			else if(*code == 1) printf("\nICMP Type: %d\nICMP Code: %d\nFragment Reassembly Time Exceeded", *type, *code);
			else printf("\nICMP Type: %d\nICMP Code: %d\nTime Exceeded", *type, *code);
			break;
		case 12:
			switch(*code) {
				case 0:
					printf("\nICMP Type: %d\nICMP Code: %d\nParameter Problem: Pointer Indicates Error", *type, *code);
					break;
				case 1:
					printf("\nICMP Type: %d\nICMP Code: %d\nParameter Problem: Missing Required Option", *type, *code);
					break;
				case 2:
					printf("\nICMP Type: %d\nICMP Code: %d\nParameter Problem: Bad Length",
							*type, *code);
					break;
				default:
					printf("\nICMP Type: %d\nICMP Code: %d\nParameter Problem", *type, *code);
					break;
			}
			break;
		case 13:
			if(*code == 0) printf("\nICMP Type: %d\nICMP Code: %d\nTimestamp", *type, *code);
			else printf("\nICMP Type: %d\nICMP Code: %d\nUsed for Time Synchronization", *type, *code);
			break;
		case 14:
			if(*code == 0) printf("\nICMP Type: %d\nICMP Code: %d\nTimestamp reply", *type, *code);
			else printf("\nICMP Type: %d\nICMP Code: %d\nReply to Timestamp Message", *type, *code);
			break;
		default:
			printf("\nICMP Type: %d\nICMP Code: %d", *type, *code);
			break;
	}
}

/* ICMP Analysis */
void icmpAnalysis(icmp_header* icmp_h, u_char* index, unsigned int *icmp) {
	++(*icmp);
	*index += sizeof(icmp_header);
	printf("\nICMP");
	print_icmp_desc(&icmp_h->type, &icmp_h->code);
	printf("\nICMP Header Checksum: %x", icmp_h->cks);
}

