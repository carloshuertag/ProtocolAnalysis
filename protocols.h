#include <pcap.h>
/* IPv4 Address */
typedef struct ipv4_address {
	u_char a;
	u_char b;
	u_char c;
	u_char d;
} ipv4_address;

/*IPv4 Header*/
typedef struct ipv4_header {
	u_char version_ihl;
	u_char tos;
	u_short tlen;
	u_short identifier;
	u_short flags_fragmentOffest;
	u_char ttl;
	u_char protocol;
	u_short cheksum;
	ipv4_address source_address;
	ipv4_address destination_address;
	u_char options_padding[40];
} ipv4_header;

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

void print_sap_protocol(const u_char *sap){
	switch((u_short)*sap) {
		case 0:
			printf("\nSAP %.2x Protocol: Null SAP", sap);
			break;
		case 4:
			printf("\nSAP %.2x Protocol: SNA", sap);
			break;
		case 5:
			printf("\nSAP %.2x Protocol: SNA", sap);
			break;
		case 6:
			printf("\nSAP %.2x Protocol: TCP", sap);
			break;
		case 8:
			printf("\nSAP %.2x Protocol: SNA", sap);
			break;
		case 12:
			printf("\nSAP %.2x Protocol: SNA", sap);
			break;
		case 66:
			printf("\nSAP %.2x Protocol: Spanning Tree", sap);
			break;
		case 127:
			printf("\nSAP %.2x Protocol: ISO 802.2", sap);
			break;
		case 128:
			printf("\nSAP %.2x Protocol: XNS", sap);
			break;
		case 170:
			printf("\nSAP %.2x Protocol: SNAP", sap);
			break;
		case 224:
			printf("\nSAP %.2x Protocol: IPX", sap);
			break;
		case 240:
			printf("\nSAP %.2x Protocol: NetBIOS", sap);
			break;
		case 248:
			printf("\nSAP %.2x Protocol: RPL", sap);
			break;
		case 252:
			printf("\nSAP %.2x Protocol: RPL", sap);
			break;
		case 254:
			printf("\nSAP %.2x Protocol: OSI", sap);
			break;
		case 255:
			printf("\nSAP %.2x Protocol: Global SAP", sap);
			break;
		default:
			printf("\nSAP %.2x Uncommon protocol", sap);
			break;
	}
}

void print_pkt_scode(u_short code) {
	switch(code) {
		case 0:
			printf("\nSupervisory: 00 - RR, Receive ready");
			break;
		case 1:
			printf("\nSupervisory: 01 - REJ, Reject");
			break;
		case 2:
			printf("\nSupervisory: 10 - RNR, Recieve not ready");
			break;
		case 3:
			printf("\nSupervisory Code: 11 - SREJ, Selective reject");
			break;
	}
}

void print_pkt_umode(const u_char *mode) {
	u_short m = (((*mode) >> 2) & 1) * 16 + (((*mode) >> 3) & 1) * 8 + (((*mode) >> 5) & 1) * 4 +
		(((*mode) >> 6) & 1) * 2 + (((*mode) >> 7) & 1) * 1;
	switch(m) {
		case 0:
			printf("\nUnnumbered bits: 00001 - UI, Unnamed information");
			break;
		case 1:
			printf("\n Unnumbered bits: 00001 - SNRM, Set Normal Mode");
			break;
		case 2:
			printf("\nUnnumbered bits: 00001 - DISC/RD, Disconnect/Request Disconnect");
			break;
		case 4:
			printf("\nUnnumbered bits: 00001 - UP, Unnamed sample");
			break;
		case 6:
			printf("\nUnnumbered bits: 00001 - UA, Unnamed acknoledgement");
			break;
		case 16:
			printf("\nUnnumbered bits: 00001 - SIM/RIM, Set Init Mode/Request information mode");
			break;
		case 17:
			printf("\nUnnumbered bits: 00001 - FRMR, Frame Reject");
			break;
		case 25:
			printf("\nU Packet Unnumbered bits: 00001 - RSET, Reset");
			break;
		case 27:
			printf("\nU Packet Unnumbered bits: 00001 - SNRME, Set Normal Mode Extended");
			break;
		case 28:
			printf("\nU Packet Unnumbered bits: 00001 - SABM, Set Asynchronous Balanced Mode");
			break;
		case 29:
			printf("\nU Packet Unnumbered bits: 11110 - XID, Exchange Identification");
			break;
		case 30:
			printf("\nU Packet Unnumbered bits: 11110 - SABME,  Set Asynchronous Balanced Mode Extended");
			break;
	}
}

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

void print_opCode (const u_char *opCode0, const u_char *opCode1){
	u_short hwType = *opCode0 * 255 + *opCode1;
	switch (hwType) {
		case 1:
			printf("\nOperation code: 1 - ARP Request");
			break;
		case 2:
			printf("\nOperation code: 2 - ARP Reply");
			break;
		case 3:
			printf("\nOperation code: 3 - RARP Request");
			break;
		case 4:
			printf("\nOperation code: 4 - RARP Reply");
			break;
		default:
			printf("\nOperation code: Unidentified");
			break;
	}
}

void print_ipProtocol(const u_char *protocol) {
	switch(*protocol) {
		case 0:
			printf("\nTransport protocol type: Reserved");
			break;
		case 1:
			printf("\nTransport protocol type: ICMP (Internet Control Message)");
			break;
		case 2:
			printf("\nTransport protocol type: IGMP (Internet Group Management)");
			break;
		case 3:
			printf("\nTransport protocol type: GGP (Gateway-to-Gateway)");
			break;
		case 4:
			printf("\nTransport protocol type: IP (IP in IP [encasulation])");
			break;
		case 5:
			printf("\nTransport protocol type: ST (Stream)");
			break;
		case 6:
			printf("\nTransport protocol type: TCP (Transmission Control)");
			break;
		case 7:
			printf("\nTransport protocol type: UCL");
			break;
		case 8:
			printf("\nTransport protocol type: EGP (Exterior Gateway Protocol)");
			break;
		case 9:
			printf("\nTransport protocol type: IGP (any private interior gateway)");
			break;
		case 10:
			printf("\nTransport protocol type: BBN-RCC-MON (BBN RCC Monitoring)");
			break;
		case 11:
			printf("\nTransport protocol type: NVP-11 (Network Voice Protocol)");
			break;
		case 12:
			printf("\nTransport protocol type: PUP");
			break;
		case 13:
			printf("\nTransport protocol type: ARGUS");
			break;
		case 14:
			printf("\nTransport protocol type: EMCON");
			break;
		case 15:
			printf("\nTransport protocol type: XNET (Cross Net Debugger)");
			break;
		case 16:
			printf("\nTransport protocol type: CHAOS (Chaos)");
			break;
		case 17:
			printf("\nTransport protocol type: UDP (User Datagram)");
			break;
		case 18:
			printf("\nTransport protocol type: MUX (Multiplexing)");
			break;
		case 19:
			printf("\nTransport protocol type: DCN-MEAS (DCN Measurement Subsystems)");
			break;
		case 20:
			printf("\nTransport protocol type: HMP (Host Monitoring)");
			break;
		case 21:
			printf("\nTransport protocol type: PRM (Packet Radio Measurement)");
			break;
		case 22:
			printf("\nTransport protocol type: XNS-IDP (XEROX NS IDP)");
			break;
		case 23:
			printf("\nTransport protocol type: TRUNK-1 (Trunk-1)");
			break;
		case 24:
			printf("\nTransport protocol type: TRUCK-2 (Trunk-2)");
			break;
		case 25:
			printf("\nTransport protocol type: LEAF-1 (Leaf-1)");
			break;
		case 26:
			printf("\nTransport protocol type: LEAF-2 (Leaf-2)");
			break;
		case 27:
			printf("\nTransport protocol type: RDP (Reliable Data Protocol)");
			break;
		case 28:
			printf("\nTransport protocol type: IRTP (Internet Reliable Transaction)");
			break;
		case 29:
			printf("\nTransport protocol type: ISO-TP4 (ISO Transport Protocol Class 4)");
			break;
		case 30:
			printf("\nTransport protocol type: NETBLT (Bulk Data Transfer Protocol)");
			break;
		case 31:
			printf("\nTransport protocol type: MFE-NSP (MFE Network Services Protocol)");
			break;
		case 32:
			printf("\nTransport protocol type: MERIT-INP (MERIT Internodal Protocol)");
			break;
		case 33:
			printf("\nTransport protocol type: SEP (Sequential Exchange Protocol)");
			break;
		case 34:
			printf("\nTransport protocol type: 3PC (Third Party Connect Protocol)");
			break;
		case 35:
			printf("\nTransport protocol type: IDPR (Inter-Domain Policy Routing Protocol)");
			break;
		case 36:
			printf("\nTransport protocol type: XTP ");
			break;
		case 37:
			printf("\nTransport protocol type: DDP (Datagram Delivery Protocol)");
			break;
		case 38:
			printf("\nTransport protocol type: IDPR-CMTP (IDPR Control Message Transport Protocol)");
			break;
		case 39:
			printf("\nTransport protocol type: TP++ (Transport Protocol)");
			break;
		case 40:
			printf("\nTransport protocol type: IL (IL Transport Protocol)");
			break;
		case 61:
			printf("\nTransport protocol type: (any host internal protocol)");
			break;
		case 62:
			printf("\nTransport protocol type: CFTP");
			break;
		case 63:
			printf("\nTransport protocol type: (any local network)");
			break;
		case 64:
			printf("\nTransport protocol type: SAT-EXPAK (SATNET and Backroom EXPAK)");
			break;
		case 65:
			printf("\nTransport protocol type: KRYPTOLAN");
			break;
		case 66:
			printf("\nTransport protocol type: RVD (MIT Remote Virtual Disk Protocol)");
			break;
		case 67:
			printf("\nTransport protocol type: IPPC (Internet Pluribus Packet Core)");
			break;
		case 68:
			printf("\nTransport protocol type: (any distributed file system)");
			break;
		case 69:
			printf("\nTransport protocol type: SAT-MON (SATNET Monitoring)");
			break;
		case 70:
			printf("\nTransport protocol type: VISA (VISA Protocol)");
			break;
		case 71:
			printf("\nTransport protocol type: IPCV (Internet Packet Core Utility)");
			break;
		case 72:
			printf("\nTransport protocol type: CPNX (Computer Protocol Network Executive)");
			break;
		case 73:
			printf("\nTransport protocol type: CPHB (Computer Protocol Heart Beat)");
			break;
		case 74:
			printf("\nTransport protocol type: WSN (Wang Span Network)");
			break;
		case 75:
			printf("\nTransport protocol type: PVP (Packet Video Protocol)");
			break;
		case 76:
			printf("\nTransport protocol type: BR-SAT-MON (Backroom SATNET Monitoring)");
			break;
		case 77:
			printf("\nTransport protocol type: SUN-ND (SUN ND PROTOCOL-Temporary )");
			break;
		case 78:
			printf("\nTransport protocol type: WB-MON (WIDEBAND Monitoring)");
			break;
		case 79:
			printf("\nTransport protocol type: WB-EXPAK (WIDEBAND EXPAK)");
			break;
		case 80:
			printf("\nTransport protocol type: ISO-IP (ISO Internet Protocol)");
			break;
		case 81:
			printf("\nTransport protocol type: VMTP");
			break;
		case 82:
			printf("\nTransport protocol type: SECURE-VMTP");
			break;
		case 83:
			printf("\nTransport protocol type: VINES");
			break;
		case 84:
			printf("\nTransport protocol type: TTP");
			break;
		case 85:
			printf("\nTransport protocol type: NSFNET-IGP");
			break;
		case 86:
			printf("\nTransport protocol type: DGP (Dissimilar Gateway Protocol)");
			break;
		case 87:
			printf("\nTransport protocol type: TCF");
			break;
		case 88:
			printf("\nTransport protocol type: IGRP");
			break;
		case 89:
			printf("\nTransport protocol type: OSPFIGP");
			break;
		case 90:
			printf("\nTransport protocol type: Sprite-RPC (Sprite RPC Protocoll)");
			break;
		case 91:
			printf("\nTransport protocol type: LARP (Locus Address Resolution Protocol)");
			break;
		case 92:
			printf("\nTransport protocol type: MTP (Multicast Transport Protocol)");
			break;
		case 93:
			printf("\nTransport protocol type: AX.25 (AX.25 Frames)");
			break;
		case 94:
			printf("\nTransport protocol type: IPIP (IP-within-IP Encapsulation Protocol)");
			break;
		case 95:
			printf("\nTransport protocol type: MICP (Mobile Internetworking Control Protocol)");
			break;
		case 96:
			printf("\nTransport protocol type: AES-SP3-D (AES Security Protocol 3-D)");
			break;
		case 97:
			printf("\nTransport protocol type: ETHERIP (Ethernet-within-IP Encapsulation)");
			break;
		case 98:
			printf("\nTransport protocol type: ENCAP (Enapsulation Header)");
			break;
		case 255:
			printf("\nTransport protocol type: Reserved");
			break;
		default:
			printf("\nTransport protocol type: Unassigned");
			break;
	}
}

void print_ipTosClass(const u_char *tos) {
	switch(*tos >> 5) { // Class selector
		case 0:
			printf("\n\tClass selector: 000 (Routine, generally by default)");
			break;
		case 1:
			printf("\n\tClass selector: 001 (Priority, generally free to classify data traffic)");
			break;
		case 2:
			printf("\n\tClass selector: 010 (Inmediate, generally free to classify data traffic)");
			break;
		case 3:
			printf("\n\tClass selector: 011 (Flash, generally call signaling)");
			break;
		case 4:
			printf("\n\tClass selector: 100 (Flash Override, generally videoconferencing, streaming)");
			break;
		case 5:
			printf("\n\tClass selector: 101 (CRITIC/ECP, generally voice)");
			break;
		case 6:
			printf("\n\tClass selector: 110 (Internetwork Control, generray control traffic [e.g. routing])");
			break;
		case 7:
			printf("\n\tClass selector: 111 (Network Control, generally control traffic [e.g. routing])");
			break;
	}
}

void print_ipTos(const u_char *tos) {
	printf("\nType of Service:");
	print_ipTosClass(tos);
	switch (*tos & 3) {
		case 0:
			printf("\n\tECN: Non capable");
			break;
		case 1:
			printf("\n\tECN: Capable");
			break;
		case 2:
			printf("\n\tECN: Capable");
			break;
		case 4:
			printf("\n\tECN: Congestion found");
			break;
	}
}

const u_char ipv4Analysis (ipv4_header *ip_header) {
	u_char ihl = (ip_header->version_ihl & 15) * 4, i;
	printf("\nIP PDU\nInternet Protocol Version: %d\nIHL (IP Header Length): %d",
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
	printf("\nHeader checksum: %d", ip_header->cheksum); //Cheksum
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
	return ihl;
}

