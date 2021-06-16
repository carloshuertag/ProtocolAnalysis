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
} igmp_group_record;

/*IGMPv3 Header*/
typedef struct igmpv3_header {
    u_char type; //IGMP type
    u_char rsv1; //reserved1
    u_short cks; //checksum
    u_short rsv2; //resserved2
    u_short ngr; //group records number
} igmpv3_header;

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

void print_igmp_rtype(u_char *type) {
	switch(*type) {
		case 1:
			printf("\nRecord Type: MODE_IS_INCLUDE");
			break;
		case 2:
			printf("\nRecord Type: MODE_IS_EXCLUDE");
			break;
		case 3:
			printf("\nRecord Type: CHANGE_TO_INCLUDE_MODE");
			break;
		case 4:
			printf("\nRecord Type: CHANGE_TO_EXCLUDE_MODE");
			break;
		case 5:
			printf("\nRecord Type: ALLOW_NEW_SOURCES");
			break;
		case 6:
			printf("\nRecord Type: BLOCK_OLD_SOURCES");
			break;
		default:
			printf("\nRecord Type: Unrecognized");
			break;
	}
}

