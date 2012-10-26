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

int sock_raw;

struct sockaddr_in source,dest;

int		main()
{
  int		saddr_size;
  int		data_size;
  struct sockaddr saddr;
  //  struct in_addr in;  
  unsigned char *buffer = malloc(sizeof(unsigned char *) * 65536);
  t_sniffer	sniffer;// = malloc(sizeof(t_sniffer *));

  sniffer.logfile = fopen("log.txt", "w");
  fprintf(sniffer.logfile,"toto42\n");
  if (sniffer.logfile == NULL)
    {
      perror("fopen(): ");
      return (EXIT_FAILURE);
    }
  sniffer.prot = malloc(sizeof(t_protocol *));
  printf("Starting at %s\n", __DATE__);
  sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock_raw < 0)
    {
      perror("socket(): ");
      return (EXIT_FAILURE);
    }
  while (1)
    {
      saddr_size = sizeof(saddr);
      data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
      if (data_size < 0)
	{
	  close(sock_raw);
	  perror("recvfrom(): ");
	  return (EXIT_FAILURE);
	}
      ProcessPacket(buffer, data_size, &sniffer);
    }
  close(sock_raw);
  return (EXIT_SUCCESS);
}

void ProcessPacket(unsigned char* buffer, int size, t_sniffer *sniffer)
{
  //Get the IP Header part of this packet
  struct iphdr *iph = (struct iphdr*)buffer;
  ++sniffer->prot->total;
  switch (iph->protocol) //Check the Protocol and do accordingly...
    {
    case 1:  //ICMP Protocol
      ++sniffer->prot->icmp;
      //PrintIcmpPacket(Buffer,Size);
      break;
      
    case 2:  //IGMP Protocol
      ++sniffer->prot->igmp;
      break;
      
    case 6:  //TCP Protocol
      ++sniffer->prot->tcp;
      print_tcp_packet(buffer , size, sniffer);
      break;
      
    case 17: //UDP Protocol
      ++sniffer->prot->udp;
      print_udp_packet(buffer , size, sniffer);
      break;
      
    default: //Some Other Protocol like ARP etc.
      ++sniffer->prot->others;
      break;
    }
  printf("\nTCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n",
	 sniffer->prot->tcp, sniffer->prot->udp,
	 sniffer->prot->icmp, sniffer->prot->igmp,
	 sniffer->prot->others, sniffer->prot->total);
}


void print_ip_header(unsigned char* Buffer, int Size, t_sniffer *sniffer)
{
  unsigned short iphdrlen;
  
  struct iphdr *iph = (struct iphdr *)Buffer;
  iphdrlen = iph->ihl*4;
  (void)iphdrlen;
  (void)Size;
  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;
  
  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = iph->daddr;
  
  fprintf(sniffer->logfile,"\n");
  fprintf(sniffer->logfile,"IP Header\n");
  fprintf(sniffer->logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
  fprintf(sniffer->logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
  fprintf(sniffer->logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
  fprintf(sniffer->logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
  fprintf(sniffer->logfile,"   |-Identification    : %d\n",ntohs(iph->id));
  fprintf(sniffer->logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
  fprintf(sniffer->logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
  fprintf(sniffer->logfile,"   |-Checksum : %d\n",ntohs(iph->check));
  fprintf(sniffer->logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
  fprintf(sniffer->logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size, t_sniffer *sniffer)
{
  unsigned short iphdrlen;
  
  struct iphdr *iph = (struct iphdr *)Buffer;
  iphdrlen = iph->ihl*4;
  
  struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
  printf("print_tcp_packet() -> (%p)\n", sniffer->logfile);  
  fprintf(sniffer->logfile,"\n\n***********************TCP Packet*************************\n");
  
  print_ip_header(Buffer, Size, sniffer);
  
  fprintf(sniffer->logfile,"\n");
  fprintf(sniffer->logfile,"TCP Header\n");
  fprintf(sniffer->logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
  fprintf(sniffer->logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
  fprintf(sniffer->logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
  fprintf(sniffer->logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
  fprintf(sniffer->logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
  //fprintf(sniffer->logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
  //fprintf(sniffer->logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
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
  PrintData(Buffer, iphdrlen, sniffer);
  
  fprintf(sniffer->logfile,"TCP Header\n");
  PrintData(Buffer+iphdrlen, tcph->doff*4, sniffer);
  
  fprintf(sniffer->logfile,"Data Payload\n");
  PrintData(Buffer + iphdrlen + tcph->doff*4,
	    (Size - tcph->doff*4-iph->ihl*4),
	    sniffer );
  
  fprintf(sniffer->logfile,"\n###########################################################");
}

void print_udp_packet(unsigned char *Buffer , int Size, t_sniffer *sniffer)
{
  unsigned short iphdrlen;

  struct iphdr *iph = (struct iphdr *)Buffer;
  iphdrlen = iph->ihl*4;
  
  struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);
  
  fprintf(sniffer->logfile,"\n\n***********************UDP Packet*************************\n");
  
  print_ip_header(Buffer, Size, sniffer);
  
  fprintf(sniffer->logfile,"\nUDP Header\n");
  fprintf(sniffer->logfile,"   |-Source Port      : %d\n" , ntohs(udph->source));
  fprintf(sniffer->logfile,"   |-Destination Port : %d\n" , ntohs(udph->dest));
  fprintf(sniffer->logfile,"   |-UDP Length       : %d\n" , ntohs(udph->len));
  fprintf(sniffer->logfile,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));
  
  fprintf(sniffer->logfile,"\n");
  fprintf(sniffer->logfile,"IP Header\n");
  PrintData(Buffer , iphdrlen, sniffer);
  
  fprintf(sniffer->logfile,"UDP Header\n");
  PrintData(Buffer+iphdrlen, sizeof(udph), sniffer);
  
  fprintf(sniffer->logfile,"Data Payload\n");
  PrintData(Buffer + iphdrlen + sizeof udph,
	    (Size - sizeof udph - iph->ihl * 4),
	    sniffer);
  
  fprintf(sniffer->logfile,"\n###########################################################");
}

void print_icmp_packet(unsigned char* Buffer , int Size, t_sniffer *sniffer)
{
  unsigned short iphdrlen;
  
  struct iphdr *iph = (struct iphdr *)Buffer;
  iphdrlen = iph->ihl*4;
  
  struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
  
  fprintf(sniffer->logfile,"\n\n***********************ICMP Packet*************************\n");
  
  print_ip_header(Buffer , Size, sniffer);
  
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
  PrintData(Buffer, iphdrlen, sniffer);
  
  fprintf(sniffer->logfile,"UDP Header\n");
  PrintData(Buffer + iphdrlen , sizeof(icmph), sniffer);
  
  fprintf(sniffer->logfile,"Data Payload\n");
  PrintData(Buffer + iphdrlen + sizeof(icmph),
	    (Size - sizeof(icmph) - iph->ihl * 4),
	    sniffer);
  
  fprintf(sniffer->logfile,"\n###########################################################");
}

void PrintData (unsigned char* data , int Size, t_sniffer *sniffer)
{
  int i,j;
  for(i=0 ; i < Size ; i++)
    {
      if( i!=0 && i%16==0)   //if one line of hex printing is complete...
	{
	  fprintf(sniffer->logfile,"         ");
	  for(j=i-16 ; j<i ; j++)
	    {
	      if(data[j]>=32 && data[j]<=128)
		fprintf(sniffer->logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
	      
	      else fprintf(sniffer->logfile,"."); //otherwise print a dot
	    }
	  fprintf(sniffer->logfile,"\n");
	} 
      
      if(i%16==0) fprintf(sniffer->logfile,"   ");
      fprintf(sniffer->logfile," %02X",(unsigned int)data[i]);
      
      if( i==Size-1)  //print the last spaces
	{
	  for(j=0;j<15-i%16;j++) fprintf(sniffer->logfile,"   "); //extra spaces
	  
	  fprintf(sniffer->logfile,"         ");
	  
	  for(j=i-i%16 ; j<=i ; j++)
	    {
	      if(data[j]>=32 && data[j]<=128) fprintf(sniffer->logfile,"%c",(unsigned char)data[j]);
	      else fprintf(sniffer->logfile,".");
	    }
	  fprintf(sniffer->logfile,"\n");
	}
    }
}
