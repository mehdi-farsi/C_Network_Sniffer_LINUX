#include	<unistd.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<netinet/ip.h>
#include	<sys/socket.h>
#include	<fcntl.h>
#include	<sys/types.h>
#include	<sys/time.h>
#include	<errno.h>

#include	"sniffer.h"
#include	"tools.h"

int		exec_cmd(char *buffer, int len)
{
  if (strncmp(buffer, "quit", 4) == 0)
    return (1);
  return (0);
}

int		command_interpreter(int sd)
{
  int		mode;
  int		mode_socket;
  int		len;
  char		buf[512];

  mode = fcntl(0, F_GETFL, 0);
  mode |= O_NONBLOCK;
  fcntl(0, F_SETFL, mode);

  mode_socket = fcntl(sd, F_GETFL, 0);
  mode_socket |= O_NONBLOCK;
  fcntl(sd, F_SETFL, mode_socket);

  len = read(0, buf, 512);
  if (len > 0)
    {
      printf(">> %.*s\n", len, buf);     
      if (exec_cmd(buf, len) == 1)
	return (1);
    }
    return (0);
}

void		display_time_and_date()
{
  INITCOLOR(RED_COLOR);
  printf("[%s]", __DATE__);
  INITCOLOR(GREEN_COLOR);
  printf("[%s]  ", __TIME__);
  INITCOLOR(ZERO_COLOR);
}

void		getting_started()
{
  CLEARSCREEN();
  display_time_and_date();
  printf("Getting started of Network sniffer\n\n");  
}

int		main()
{
  int		sd;
  int		saddr_size;
  int		data_size;
  struct sockaddr saddr;
  unsigned char *buffer;
  t_sniffer	sniffer;
  //  struct fd_set	fd_read;

  buffer = malloc(sizeof(unsigned char *) * 65536);
  sniffer.logfile = fopen("log.txt", "w");
  fprintf(sniffer.logfile,"***LOGFILE(%s - %s)***\n", __DATE__, __TIME__);
  if (sniffer.logfile == NULL)
    {
      perror("fopen(): ");
      return (EXIT_FAILURE);
    }
  sniffer.prot = malloc(sizeof(t_protocol *));
  sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sd < 0)
    {
      perror("socket(): ");
      return (EXIT_FAILURE);
    }
  getting_started();

  while (1)
    {
      
      if (command_interpreter(sd) == 1)
	break;
      saddr_size = sizeof(saddr);
      data_size = recvfrom(sd, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
      if (data_size > 0)
	{
	  ProcessPacket(buffer, data_size, &sniffer);
	  //close(sd);
	  //perror("recvfrom(): ");
	  //return (EXIT_FAILURE);
	}

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
  display_time_and_date();
  printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d Total : %d\n",
	 sniffer->prot->tcp, sniffer->prot->udp,
	 sniffer->prot->icmp, sniffer->prot->igmp,
	 sniffer->prot->others, sniffer->prot->total);
}

