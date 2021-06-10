/*ICMP Header*/
typedef struct icmp_heaader {
	u_char type;
	u_char code; 
	u_short cks;
} icmp_header;

/*IGMPv1 Header*/
typedef struct igmpv1_header {
    u_char version_type; //IGMP version & type
    u_char unused; //unused
    u_short cks; //checksum
    ipv4_address group_addrss; //group address
} igmpv1_header;

/*IGMPv2 Header*/
typedef struct igmpv2_header {
    u_char type; //IGMP type
    u_char mxrsptm; //max response time
    u_short cks; //checksum
    ipv4_address group_addrss; //group address
} igmpv2_header;

/*IGMP Group Record*/
typedef struct igmp_group_record {
    u_char rtype; //record type
    u_char auxlen; //auxiliary data length
    u_short nsrc; //number of sources
    ipv4_address multicast_addrss; //multicast address
    ipv4_address *src_addrsss; //source adresses
    u_char *aux_data; //auxiliary data
} igmp_group_record;

/*IGMPv3 Header*/
typedef struct igmpv3_header {
    u_char type; //IGMP type
    u_char rsv1; //reserved1
    u_short cks; //checksum
    u_short rsv2; //resserved2
    u_short ngr; //groups of records number
    igmp_group_record group_record; //group record
} igmpv3_header;

void igmpAnalysis(u_char* igmp_pdu, u_char* index, int* igmp) {
	//*index += sizeof(igmp_header);
    ++(*igmp);
}

void print_igmp_type(u_char *type) {
	switch(*type) {
		case 17:
			printf("\nIGMP Message Type: Membership Query");
			break;
		case 18:
			printf("\nIGMP Message Type: IGMPv1 Membership Report");
			break;
		case 22:
			printf("\nIGMP Message Type: IGMPv2 Membership Report");
			break;
		case 23:
			printf("\nIGMP Message Type: Leave Group");
			break;
		case 34:
			printf("\nIGMP Message Type: IGMPv3 Membership Report");
			break;
		default:
			printf("\nIGMP Message Type: Unidentified");
			break;
	}
}

