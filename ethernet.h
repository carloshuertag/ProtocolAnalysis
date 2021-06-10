/* Prints tha packet type from an Ethernet packet */
void print_pkt_type (u_short *pkt_type, const u_char *t_byte0, const u_char *t_byte1) {
	switch(*pkt_type) {
		case 1536:
			printf("\nPacket type %02X %02X (%d): XEROX NS IDP", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2048:
			printf("\nPacket type %02X %02X (%d): DOD IP", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2049:
			printf("\nPacket type %02X %02X (%d): X.75 Internet", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2050:
			printf("\nPacket type %02X %02X (%d): NBS Internet", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2051:
			printf("\nPacket type %02X %02X (%d): ECMA Internet", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2052:
			printf("\nPacket type %02X %02X (%d): Chaoset", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2053:
			printf("\nPacket type %02X %02X (%d): X.25 Level 3", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2054:
			printf("\nPacket type %02X %02X (%d): ARP", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2055:
			printf("\nPacket type %02X %02X (%d): XNS Compatibility", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2076:
			printf("\nPacket type %02X %02X (%d): Symbolics Private", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2184:
			printf("\nPacket type %02X %02X (%d): Xyplex", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2304:
			printf("\nPacket type %02X %02X (%d): Ungermann-Bass net debugr", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2560:
			printf("\nPacket type %02X %02X (%d): Xerox IEEE 802.3 PUP", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2561:
			printf("\nPacket type %02X %02X (%d): PUP Addr Trans", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 2989:
			printf("\nPacket type %02X %02X (%d): Banyan Systems", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 4096:
			printf("\nPacket type %02X %02X (%d): Berkely Trailer nego", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 4097:
			printf("\nPacket type %02X %02X (%d): Berkely Trailer encap/IP", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 5632:
			printf("\nPacket type %02X %02X (%d): Valid System", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 16962:
			printf("\nPacket type %02X %02X (%d): PCS basic Block Protocol", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 21000:
			printf("\nPacket type %02X %02X (%d): BBN Simmet", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 24577:
			printf("\nPacket type %02X %02X (%d): DEC MOP Dump/Load", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 24578:
			printf("\nPacket type %02X %02X (%d): DEC MOP Remote Console", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 24579:
			printf("\nPacket type %02X %02X (%d): DEC DECNET Phase IV Route", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 24580:
			printf("\nPacket type %02X %02X (%d): DEC LAT", *t_byte0, *t_byte1, *pkt_type);
			break;
		case 24581:
			printf("\nPacket type %02X %02X (%d): DEC Diagnostic Protocol", *t_byte0, *t_byte1, *pkt_type);
			break;
		default:
			printf("\nPacket type %02X %02X (%d)", *t_byte0, *t_byte1, *pkt_type);
			break;
	}
}

