#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <time.h> 

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#define MY_DEST_MAC0  0x00
#define MY_DEST_MAC1  0x00
#define MY_DEST_MAC2  0x00
#define MY_DEST_MAC3  0x00
#define MY_DEST_MAC4  0x00
#define MY_DEST_MAC5  0x0a

#define DEFAULT_IF  "h1-eth0"
#define BUF_SIZ   1024


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp{
	u_short udp_sport;
	u_short udp_dport;
	u_short udp_length; // the length of udp header + payload
	u_short udp_sum; //checksum
};

int packetCounter = 0;
int barrier = 0;
time_t startTime;
char *dev = NULL;
char *srcIP = NULL;
int sockfd;
struct ifreq if_idx;
struct ifreq if_mac;
struct sockaddr_ll socket_address;
char ifName[IFNAMSIZ];

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void printLine(const u_char *payload, int len, int offset);


void printLine(const u_char *payload, int len, int offset)
{
	int i;
	int gap;

	const u_char *ch = payload;

	printf("     ");
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		printLine(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		printLine(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			printLine(ch, len_rem, offset);
			break;
		}
	}

	return;
}


void* utilFunc(void* ptr)
{

}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//barrier = 1;

	static int count = 1;//packet counter
	//declare pointers to packet headers
	const struct sniff_ethernet* ether;//Ethernet header
	const struct sniff_ip* ip;//IP header
	const struct sniff_tcp* tcp;//TCP header
	const struct sniff_udp* udp;//UDP header
	const char *payload;//Packet payload

	int size_ethernet = 14;
	int size_ip;
	int size_tcp;
	int size_payload;

	packetCounter = packetCounter + 1;

	printf("\nPacket number %d:\n", count);
	count++;

	ether = (struct sniff_ethernet*) packet;
	printf("Ether shost: \n");

	for(int i=0; i < ETHER_ADDR_LEN; i++)
		printf("%02x ", ether->ether_shost[i]);
	printf("\n");

	printf("Ether dhost: \n");
	for(int i=0; i < ETHER_ADDR_LEN; i++)
		printf("%02x ", ether->ether_dhost[i]);
	printf("\n");

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + size_ethernet);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {		
		printf("   Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	if(strcmp(inet_ntoa(ip->ip_src), "10.0.6.1") == 0){//Tunneled (Tunneled packets sent as UDP packets.)
		packet += size_ethernet + size_ip + 8;//Reach the encapsulated packet
		ip = (struct sniff_ip*)(packet);
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("   Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		size_ethernet = 0;//encapsulated packets does not have an ethernet field.
	}

	
	/* determine protocol */	
	switch(ip->ip_p) 
	{
		case IPPROTO_TCP:
				/* print source and destination IP addresses */
				printf("   From: %s\n", inet_ntoa(ip->ip_src));
				printf("   To: %s\n", inet_ntoa(ip->ip_dst));	
				printf("   Protocol: TCP\n");
				/* define/compute tcp header offset */
				tcp = (struct sniff_tcp*)(packet + size_ethernet + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if (size_tcp < 20) {
					printf("   Invalid TCP header length: %u bytes\n", size_tcp);
					return;
				}
				printf("   Src port: %d\n", ntohs(tcp->th_sport));
				printf("   Dst port: %d\n", ntohs(tcp->th_dport));
				payload = (u_char *)(packet + size_ethernet + size_ip + size_tcp);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
				if (size_payload > 0) {
					printf("   Payload (%d bytes):\n", size_payload);
					print_payload(payload, size_payload);
				}	
			return;

		case IPPROTO_UDP:
			/* print source and destination IP addresses */
			printf("   From: %s\n", inet_ntoa(ip->ip_src));
			printf("   To: %s\n", inet_ntoa(ip->ip_dst));		
			printf("   Protocol: UDP\n");
			udp = (struct sniff_udp*) (packet + size_ethernet + size_ip);
			printf("   Src port: %d\n", ntohs(udp->udp_sport));
			printf("   Dst port: %d\n", ntohs(udp->udp_dport));	
			payload = (u_char *)(packet + size_ethernet + size_ip + 8);//udp_size = 8
			size_payload = ntohs(ip->ip_len) - (size_ip + 8);//udp_size = 8
			if (size_payload > 0) {
				printf("   Payload (%d bytes):\n", size_payload);
				print_payload(payload, size_payload);
			}
			return;

		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
return;
}

int main(int argc, char **argv)
{
	time(&startTime);

	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	if(dev[1] == 50 || dev[1] == 51 || dev[1] == 52 || dev[1] == 53)
	{
		if(dev[1] == 50) {
			strcpy(ifName, "h2-eth1");
			srcIP = "10.0.13.0";
		}
		if(dev[1] == 51) {
			strcpy(ifName, "h3-eth1");
			srcIP = "10.0.13.2";
		}
		if(dev[1] == 52) {
			strcpy(ifName, "h4-eth1");
			srcIP = "10.0.13.4";
		}
		if(dev[1] == 53) {
			strcpy(ifName, "h5-eth1");
			srcIP = "10.0.13.6";
		}

	  	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	     	 perror("socket");
	  	}

	  	memset(&if_idx, 0, sizeof(struct ifreq));
	  	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	  	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	      	perror("SIOCGIFINDEX");
	  	memset(&if_mac, 0, sizeof(struct ifreq));
	  	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	  	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	      	perror("SIOCGIFHWADDR");
		pthread_t utilThread;
		pthread_create(&utilThread, NULL, utilFunc, NULL);
	}

	pcap_setdirection(handle, PCAP_D_IN);

	/* now we can set our callback function */
	pcap_loop(handle, -1 , got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}


