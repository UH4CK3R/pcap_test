#include <pcap/pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ip *iph; // IP header structure
struct tcphdr *tcph; // TCP header structure

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ether_header *ep;
    unsigned short ether_type;    
    int i;

    ep = (struct ether_header *)packet;
    packet += sizeof(struct ether_header);
    ether_type = ntohs(ep->ether_type);

    if (ether_type == ETHERTYPE_IP) // IP
    {
        iph = (struct ip *)packet;

        if (iph->ip_p == IPPROTO_TCP) // TCP
        {
                tcph = (struct tcphdr *)(packet + iph->ip_hl * 4); // packet + strlen(header)
                printf("[ Ipv%d ]\n", iph->ip_v);
                printf("SRC: [ ");
                for (i=0; i<ETH_ALEN; ++i) printf("%02x ", ep->ether_shost[i]);
                printf("] / %s:%d\n", inet_ntoa(iph->ip_src),ntohs(tcph->th_sport));
                printf("DST: [ ");
                for (i=0; i<ETH_ALEN; ++i) printf("%02x ", ep->ether_dhost[i]);
                printf("] / %s:%d\n", inet_ntoa(iph->ip_dst),ntohs(tcph->th_dport));
                printf("======================================================\n");

        }
    }

}

int main()
{
    char *device; // network device
    char *net; // IP Address
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE]; //buf for error msg

    struct in_addr net_addr;

    pcap_t *pcd; // discriptor

    device = pcap_lookupdev(errbuf);
    if (device == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Device: %s\n", device);

    if (pcap_lookupnet(device, &netp, &maskp, errbuf) == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    printf("IP: %s\n", net);
    printf("======================================================\n");

    pcd = pcap_open_live(device, BUFSIZ,  1, -1, errbuf);
    if (!pcd)
    {
        printf("%s\n", errbuf);
        exit(1);
    }    

    pcap_loop(pcd, 0, callback, NULL);
}

