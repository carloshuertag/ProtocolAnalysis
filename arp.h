void print_hwType (const u_char *hwType0, const u_char *hwType1){
	u_short hwType = *hwType0 * 255 + *hwType1;
	switch (hwType) {
		case 1:
			printf("\nHardware Type: 1 - Ethernet");
			break;
		case 6:
			printf("\nHardware Type: 6 - IEEE 802 Network");
			break;
		case 7:
			printf("\nHardware Type: 7 - ARCNET");
			break;
		case 15:
			printf("\nHardware Type: 15 - Frame Relay");
			break;
		case 16:
			printf("\nHardware Type: 16 - Asynchronous Transfer Mode (ATM)");
			break;
		case 17:
			printf("\nHardware Type: 17 - HDLC");
			break;
		case 18:
			printf("\nHardware Type: 18 - Fibre Channel");
			break;
		case 19:
			printf("\nHardware Type: 19 - Asynchronous Transfer Mode (ATM)");
			break;
		case 20:
			printf("\nHardware Type: 20 - Serial Line");
			break;
		default:
			printf("\nHardware Type: Unidentified");
			break;
	}
}

void print_opCode (const u_char *opCode0, const u_char *opCode1, int *arp, int *rarp){
	u_short hwType = *opCode0 * 255 + *opCode1;
	switch (hwType) {
		case 1:
			printf("\nOperation code: 1 - ARP Request");
			++(*arp);
			break;
		case 2:
			printf("\nOperation code: 2 - ARP Reply");
			++(*arp);
			break;
		case 3:
			printf("\nOperation code: 3 - RARP Request");
			++(*rarp);
			break;
		case 4:
			printf("\nOperation code: 4 - RARP Reply");
			++(*rarp);
			break;
		default:
			printf("\nOperation code: Unidentified");
			++(*arp);
			break;
	}
}