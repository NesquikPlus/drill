#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <random>

#define MY_DEST_MAC0  0x00
#define MY_DEST_MAC1  0x00
#define MY_DEST_MAC2  0x00
#define MY_DEST_MAC3  0x00
#define MY_DEST_MAC4  0x00
#define MY_DEST_MAC5  0x0a

#define DEFAULT_IF  "h1-eth0"
#define BUF_SIZ   1024

using namespace std;

int sockfd;
struct ifreq if_idx;
struct ifreq if_mac;
int tx_len = 0;
char sendbuf[BUF_SIZ];
struct sockaddr_ll socket_address;
char ifName[IFNAMSIZ];
char* distribution;
default_random_engine generator;
float distVal = 0;
//exponential_distribution<double> eDistribution(1);

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char** argv) {
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];
  const clock_t begin_time = clock();

  distribution = argv[2];
  distVal = atof(argv[3]);

  strcpy(ifName, DEFAULT_IF);

  /* Open RAW socket to send on */
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
      perror("socket");
  }

  /* Get the index of the interface to send on */
  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
      perror("SIOCGIFINDEX");
  /* Get the MAC address of the interface to send on */
  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
  if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
      perror("SIOCGIFHWADDR");

  // open capture file for offline processing
  descr = pcap_open_offline(argv[1], errbuf);
  if (descr == NULL) {
      cout << "pcap_open_live() failed: " << errbuf << endl;
      return 1;
  }

  // start packet processing loop, just like live capture
  if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
      cout << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }

  cout << "capture finished" << endl;
  cout<<"Time: "<<float(clock()-begin_time)/CLOCKS_PER_SEC<<endl;

  return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;
  char sourceIp[INET_ADDRSTRLEN];
  char destIp[INET_ADDRSTRLEN];
  u_int sourcePort, destPort;
  u_char *data;
  int dataLength = 0;
  tx_len = 0;
  string dataStr = "";

  if(distribution[0] == 'e') {
    exponential_distribution<double> eDistribution(distVal);
    double number = eDistribution(generator);
    double sleepVal = number*10000;
    //usleep(sleepVal);
  }
  if(distribution[0] == 'p') {
    poisson_distribution<int> pDistribution(distVal);
    double number = pDistribution(generator);
    //usleep(number);
  }
  if(distribution[0] == 'n') {
    //usleep(distVal);
  }

  memset(sendbuf, 0, BUF_SIZ);
  memcpy(sendbuf, packet, 1024);
  ////usleep(1.01);
  struct ether_header *eh = (struct ether_header *) sendbuf;
  ethernetHeader = (struct ether_header*)packet;
  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
    eh->ether_shost[0] = 0x00;
    eh->ether_shost[1] = 0x00;
    eh->ether_shost[2] = 0x00;
    eh->ether_shost[3] = 0x00;
    eh->ether_shost[4] = 0x00;
    eh->ether_shost[5] = 0x01;
    eh->ether_dhost[0] = MY_DEST_MAC0;
    eh->ether_dhost[1] = MY_DEST_MAC1;
    eh->ether_dhost[2] = MY_DEST_MAC2;
    eh->ether_dhost[3] = MY_DEST_MAC3;
    eh->ether_dhost[4] = MY_DEST_MAC4;
    eh->ether_dhost[5] = MY_DEST_MAC5;
    /* Ethertype field */
    eh->ether_type = htons(ETH_P_IP);
    tx_len += sizeof(struct ether_header);

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    /* Destination MAC */
    socket_address.sll_addr[0] = MY_DEST_MAC0;
    socket_address.sll_addr[1] = MY_DEST_MAC1;
    socket_address.sll_addr[2] = MY_DEST_MAC2;
    socket_address.sll_addr[3] = MY_DEST_MAC3;
    socket_address.sll_addr[4] = MY_DEST_MAC4;
    socket_address.sll_addr[5] = MY_DEST_MAC5;

    /* Send packet */
    if (sendto(sockfd, sendbuf, sizeof(sendbuf), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
        printf("Send failed\n");
  }
}
