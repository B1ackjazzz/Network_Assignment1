#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

char *dev;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){

    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct ether_header *ep;
    struct ip *ip;

    eth = (struct ethhdr *)pkt_data;
    ep = (struct ether_header *)pkt_data;

    if(ntohs(ep->ether_type) == ETHERTYPE_IP){
        iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
        ip = (struct ip *)(pkt_data + sizeof(struct ether_header));
        if(ip->ip_p == IPPROTO_TCP){
            tcph = (struct tcphdr*)(pkt_data + (ip->ip_hl) * 4 + sizeof(struct ethhdr));
            printf("---------------------------------\n");
            printf("Device : %s\n", dev);
	    printf("\n");

           printf("Src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n" ,
                     ep->ether_shost[0],
                     ep->ether_shost[1],
                     ep->ether_shost[2],
                     ep->ether_shost[3],
                     ep->ether_shost[4],
                     ep->ether_shost[5]
		);

              printf("Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n" ,
                     ep->ether_dhost[0],
                     ep->ether_dhost[1],
                     ep->ether_dhost[2],
                     ep->ether_dhost[3],
                     ep->ether_dhost[4],
                     ep->ether_dhost[5]
                     );

            printf("\n");

            printf("IP Src : %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
            printf("IP Dst : %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
           
		printf("\n");
		 printf("SRC port : %u\n",ntohs(tcph->source));
                printf("DST Port : %u\n",ntohs(tcph->dest));
            printf("--------------------------------------\n\n");
        }
    }
   else
      exit(1);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handler;

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
            printf("%s\n",errbuf);
            exit(1);
        }

    handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handler == NULL){
            printf("%s\n",errbuf);
            exit(1);
        }

    pcap_loop(handler, 0, packet_handler,NULL);

    return 0;

}

