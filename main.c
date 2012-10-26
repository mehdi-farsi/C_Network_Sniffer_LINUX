#include	<unistd.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<netinet/ip.h>
#include	<sys/socket.h>

#include	"sniffer.h"

int		main()
{
  int		sd;
  int		saddr_size;
  int		data_size;
  struct sockaddr saddr;
  unsigned char *buffer;
  t_sniffer	sniffer;

  buffer = malloc(sizeof(unsigned char *) * 65536);
  sniffer.logfile = fopen("log.txt", "w");
  fprintf(sniffer.logfile,"***LOGFILE(%s - %s)***\n", __DATE__, __TIME__);
  if (sniffer.logfile == NULL)
    {
      perror("fopen(): ");
      return (EXIT_FAILURE);
    }
  sniffer.prot = malloc(sizeof(t_protocol *));
  printf("[%s][%s]  Getting started of Network sniffer\n\n", __DATE__, __TIME__);
  sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sd < 0)
    {
      perror("socket(): ");
      return (EXIT_FAILURE);
    }
  while (1)
    {
      saddr_size = sizeof(saddr);
      data_size = recvfrom(sd, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
      if (data_size < 0)
	{
	  close(sd);
	  perror("recvfrom(): ");
	  return (EXIT_FAILURE);
	}
      ProcessPacket(buffer, data_size, &sniffer);
    }
  close(sd);
  return (EXIT_SUCCESS);
}

void ProcessPacket(unsigned char* buffer, int size, t_sniffer *sniffer)
{
  struct iphdr *iph = (struct iphdr*)buffer;
  ++sniffer->prot->total;
  switch (iph->protocol)
    {
    case 1:
      ++sniffer->prot->icmp;
      print_icmp_packet(buffer, size, sniffer);
      break;
      
    case 2:
      ++sniffer->prot->igmp;
      break;
      
    case 6:
      ++sniffer->prot->tcp;
      print_tcp_packet(buffer , size, sniffer);
      break;
      
    case 17:
      ++sniffer->prot->udp;
      print_udp_packet(buffer , size, sniffer);
      break;
      
    default:
      ++sniffer->prot->others;
      break;
    }
  printf("[%s][%s]  TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d Total : %d\n",
	 __DATE__,
	 __TIME__,
	 sniffer->prot->tcp, sniffer->prot->udp,
	 sniffer->prot->icmp, sniffer->prot->igmp,
	 sniffer->prot->others, sniffer->prot->total);
}

