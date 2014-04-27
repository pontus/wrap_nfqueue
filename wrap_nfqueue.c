#include <tcpd.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <netdb.h>



int ports[128];
char* portstrings[128];



int check_pkt(struct nfq_data* d)
{
  struct request_info* r;
  struct in_addr s_ip;

  struct sockaddr_in server;
  struct sockaddr_in client;

  struct request_info check;


  unsigned char *buf;

  int ipheadersize;
  
  uint16_t sport;
  uint16_t dport;
  int ok;
  int i;
  char* service;
  char protocol;
  char clientname[8192];
  char servername[8192];

  nfq_get_payload(d, &buf);

  ipheadersize = 4*(buf[0]&0xf);


  protocol = *((char*) buf+9);

  server.sin_family = AF_INET;
  client.sin_family = AF_INET;

  client.sin_addr.s_addr = *((uint32_t *) (buf + 12));
  server.sin_addr.s_addr = *((uint32_t *) (buf + 16));


  sport = htons( *((uint16_t*) (buf+ipheadersize)));
  dport = htons( *((uint16_t*) (buf+ipheadersize+2)));


  server.sin_port =  *((uint16_t*) (buf+ipheadersize+2));
  client.sin_port =  *((uint16_t*) (buf+ipheadersize));

  i=0;

  while(ports[i] != -1)
    {
      if (ports[i] == dport)
	{
	  service = portstrings[i];
	}

      i++;
    }

  if (getnameinfo((struct sockaddr*) &server, sizeof(server), servername, sizeof(servername)-1, NULL, 0, 0))
    {
      return NF_DROP;
    }

  if (getnameinfo((struct sockaddr*) &client, sizeof(client), clientname, sizeof(clientname)-1, NULL, 0, 0))
    {
      return NF_DROP;
    }

  r = request_init(&check,
		   RQ_DAEMON, service,
		   RQ_CLIENT_SIN, &client,
		   RQ_CLIENT_NAME, clientname,
		   RQ_SERVER_SIN, &server,
		   RQ_SERVER_NAME, servername,
		   RQ_CLIENT_ADDR, inet_ntoa(client.sin_addr),
		   0
		   );

  // fromhost(&check);
  ok = hosts_access(&check);
  
  if(ok)
    {
      return NF_ACCEPT;
    }

  return NF_DROP;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
  int ok = 1;
  // u_int32_t id = print_pkt(nfa);

  int id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  if (ph)
    {
      id = ntohl(ph->packet_id);
    }

  ok = check_pkt(nfa);

  return nfq_set_verdict(qh, id, ok, 0, NULL);
}

void usageandexit(char* name)
  {
    printf("USAGE: %s queue-number port servicename [port servicename...]\n", name);
    printf("This is <https://gist.github.com/pontus/7515300/>\n\n");
    exit(1);
  }






int main(int argc, char** argv)
{


  struct nfq_handle* nfq;
  struct nfq_q_handle* qh;
  int fd;
  int rv;

  char buf[4096] __attribute__ ((aligned));
  char* last_char;

  long int queue;



  if( argc<4 || (0 != argc %2))
    // Too few arguments or not paired list?
    {
      usageandexit(argv[0]);
    }

      queue = strtol(argv[1], &last_char, 10);

      if (last_char == argv[1])
	{
	  usageandexit(argv[0]);
	}

      int portlist = 0;
      
      while(portlist*2+2 < argc)
	{
	  ports[portlist] = strtol(argv[2+portlist*2], &last_char, 10);
	  portstrings[portlist] = argv[3+portlist*2];

	  if (last_char == argv[2+portlist*2])
	    {
	      usageandexit(argv[0]);
	    }

	  portlist++;
	}

      ports[portlist] = -1;

      
      if (daemon(0,0))
	{
	  perror("daemon failed");
	  exit(1);
	}

  nfq = nfq_open();

  if (!nfq)
    {
      fprintf(stderr, "nfq_open failed.\n");
      exit(1);
    }

  nfq_unbind_pf(nfq, AF_INET);

  if (nfq_bind_pf(nfq, AF_INET) < 0)
    {
      fprintf(stderr, "nfq_bind_pf failed\n");
      exit(1);
    }


  qh = nfq_create_queue(nfq, queue, &cb, NULL);
  if (!qh) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    exit(1);
  }


  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    exit(1);
  }

  fd = nfq_fd(nfq);

  while(1)
    {
      while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {

        nfq_handle_packet(nfq, buf, rv);
      }
    }

  return 0;
}


