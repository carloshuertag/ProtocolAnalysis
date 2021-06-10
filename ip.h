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

