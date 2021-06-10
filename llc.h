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

