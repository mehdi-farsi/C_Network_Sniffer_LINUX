#include	<unistd.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/udp.h>
#include	<netinet/tcp.h>
#include	<netinet/ip.h>
#include	<sys/socket.h>
#include	<arpa/inet.h>

#include	"sniffer.h"
#include	"tools.h"

void		print_ip_header(unsigned char *buf, int size, t_sniffer *sniffer)
{
  unsigned short iphdrlen;
  struct iphdr	*iph;
  struct sockaddr_in source;
  struct sockaddr_in dest;

  iph = (struct iphdr *)buf;
  iphdrlen = iph->ihl*4;
  (void)iphdrlen;
  (void)size;
  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;
  
  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = iph->daddr;
  
  fprintf(sniffer->logfile,"\n");
  fprintf(sniffer->logfile,"IP Header\n");
  fprintf(sniffer->logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
  fprintf(sniffer->logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
  fprintf(sniffer->logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
  fprintf(sniffer->logfile,"   |-IP Total Length   : %d  Bytes(size of Packet)\n",ntohs(iph->tot_len));
  fprintf(sniffer->logfile,"   |-Identification    : %d\n",ntohs(iph->id));
  fprintf(sniffer->logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
  fprintf(sniffer->logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
  fprintf(sniffer->logfile,"   |-Checksum : %d\n",ntohs(iph->check));
  fprintf(sniffer->logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
  fprintf(sniffer->logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void		print_tcp_packet(unsigned char *buf, int size, t_sniffer *sniffer)
{
  unsigned short iphdrlen;
  struct iphdr	*iph;
  struct tcphdr *tcph;
  
  iph = (struct iphdr *)buf;
  iphdrlen = iph->ihl * 4;  
  tcph = (struct tcphdr*)(buf + iphdrlen);
  print_ip_header(buf, size, sniffer);
  
  fprintf(sniffer->logfile,"\n");
  fprintf(sniffer->logfile,"TCP Header\n");
  fprintf(sniffer->logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
  fprintf(sniffer->logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
  fprintf(sniffer->logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
  fprintf(sniffer->logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
  fprintf(sniffer->logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
  fprintf(sniffer->logfile,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
  fprintf(sniffer->logfile,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
  fprintf(sniffer->logfile,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
  fprintf(sniffer->logfile,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
  fprintf(sniffer->logfile,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
  fprintf(sniffer->logfile,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
  fprintf(sniffer->logfile,"   |-Window         : %d\n",ntohs(tcph->window));
  fprintf(sniffer->logfile,"   |-Checksum       : %d\n",ntohs(tcph->check));
  fprintf(sniffer->logfile,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
  fprintf(sniffer->logfile,"\n");
  fprintf(sniffer->logfile,"                        DATA Dump                         ");
  fprintf(sniffer->logfile,"\n");
  
  fprintf(sniffer->logfile,"IP Header\n");
  PrintData(buf, iphdrlen, sniffer);
  
  fprintf(sniffer->logfile,"TCP Header\n");
  PrintData(buf+iphdrlen, tcph->doff*4, sniffer);
  
  fprintf(sniffer->logfile,"Data Payload\n");
  PrintData(buf + iphdrlen + tcph->doff*4,
	    (size - tcph->doff*4-iph->ihl*4),
	    sniffer );
  
  fprintf(sniffer->logfile,"\n###########################################################");
}

void		print_udp_packet(unsigned char *buf , int size, t_sniffer *sniffer)
{
  unsigned short iphdrlen;

  struct iphdr	*iph;
  struct udphdr *udph;

  iph = (struct iphdr *)buf;
  iphdrlen = iph->ihl*4;
  udph = (struct udphdr*)(buf + iphdrlen);
  fprintf(sniffer->logfile,"\n\n***********************UDP Packet*************************\n");
  
  print_ip_header(buf, size, sniffer);
  
  fprintf(sniffer->logfile,"\nUDP Header\n");
  fprintf(sniffer->logfile,"   |-Source Port      : %d\n" , ntohs(udph->source));
  fprintf(sniffer->logfile,"   |-Destination Port : %d\n" , ntohs(udph->dest));
  fprintf(sniffer->logfile,"   |-UDP Length       : %d\n" , ntohs(udph->len));
  fprintf(sniffer->logfile,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));
  
  fprintf(sniffer->logfile,"\n");
  fprintf(sniffer->logfile,"IP Header\n");
  PrintData(buf , iphdrlen, sniffer);
  
  fprintf(sniffer->logfile,"UDP Header\n");
  PrintData(buf+iphdrlen, sizeof(udph), sniffer);
  
  fprintf(sniffer->logfile,"Data Payload\n");
  PrintData(buf + iphdrlen + sizeof udph,
	    (size - sizeof udph - iph->ihl * 4),
	    sniffer);
  
  fprintf(sniffer->logfile,"\n###########################################################");
}

void		print_icmp_packet(unsigned char *buf , int size, t_sniffer *sniffer)
{
  unsigned short iphdrlen;
  struct iphdr	*iph;
  struct icmphdr *icmph;
  
  iph = (struct iphdr *)buf;
  iphdrlen = iph->ihl * 4;
  icmph = (struct icmphdr *)(buf + iphdrlen);

  fprintf(sniffer->logfile,"\n\n***********************ICMP Packet*************************\n");  
  print_ip_header(buf , size, sniffer);
  fprintf(sniffer->logfile,"\n");
  fprintf(sniffer->logfile,"ICMP Header\n");
  fprintf(sniffer->logfile,"   |-Type : %d",(unsigned int)(icmph->type));  
  if((unsigned int)(icmph->type) == 11) 
    fprintf(sniffer->logfile,"  (TTL Expired)\n");
  else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
    fprintf(sniffer->logfile,"  (ICMP Echo Reply)\n");
  fprintf(sniffer->logfile,"   |-Code : %d\n",(unsigned int)(icmph->code));
  fprintf(sniffer->logfile,"   |-Checksum : %d\n",ntohs(icmph->checksum));
  fprintf(sniffer->logfile,"\n");
  fprintf(sniffer->logfile,"IP Header\n");
  PrintData(buf, iphdrlen, sniffer);
  fprintf(sniffer->logfile,"UDP Header\n");
  PrintData(buf + iphdrlen , sizeof(icmph), sniffer);
  
  fprintf(sniffer->logfile,"Data Payload\n");
  PrintData(buf + iphdrlen + sizeof(icmph),
	    (size - sizeof(icmph) - iph->ihl * 4),
	    sniffer);
  
  fprintf(sniffer->logfile,"\n###########################################################");
}

void		PrintData(unsigned char *buf, int size, t_sniffer *sniffer)
{
  int		i;
  //  int		j;

  for(i = 0 ; i < size ; i++)
    {
      if(i % 16 == 0)
	fprintf(sniffer->logfile, "\n");
      fprintf(sniffer->logfile, " %02X",(unsigned int)buf[i]);
      
      if( i == size - 1)
	{
	  fprintf(sniffer->logfile, "\n");
	}
    }
}
