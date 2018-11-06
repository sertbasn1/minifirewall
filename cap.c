#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

char * matchip;
int matchPort;
int matchCount;
char * matchStr;

/* returns packet id */
static u_int32_t examine_pkt (struct nfq_data *tb)
{
      int id = 0;
      struct nfqnl_msg_packet_hdr *ph;
      int ret;
      char *data;
      unsigned char *user_data;
struct tcphdr *tcph; 

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

      	ret = nfq_get_payload(tb, (unsigned char**)&data);
      	if (ret >= 0){//payload_len is not eq 0
            	printf("payload_len=%d ", ret);
	       	struct iphdr * ip_info = (struct iphdr *)data;
		//printf("src addr=%d\n ", ip_info->saddr);
		//printf("dst addr=%d\n ", ip_info->daddr);
		if(ip_info->protocol == IPPROTO_TCP) {
		    struct tcphdr * tcp_info = (struct tcphdr*)(data + sizeof(*ip_info));
		    unsigned short src_port = ntohs(tcp_info->source);
		    unsigned short dest_port = ntohs(tcp_info->dest);
		    //printf("src port=%d\n ", src_port);
		    //printf("dst port=%d\n ", dest_port);

		user_data = (unsigned char *)((unsigned char *)tcp_info + (tcp_info->doff * 4));
		int c = 0;
	
		while (user_data[c]!= '\0') {
			printf("%c", user_data[c]); c=c+1;
		}
		
		//checking source port and ip adress
		if((ip_info->saddr == inet_addr(matchip)) && (src_port==matchPort))
		   printf("Packet with srcIP %s and srcPort %d is captured\n",matchip, matchPort);
		

		} else if(ip_info->protocol == IPPROTO_UDP) {
		    //etc etc
		}




	}

    fputc('\n', stdout);

      return id;
}
      

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
            struct nfq_data *nfa, void *data)
{
      u_int32_t id = examine_pkt(nfa);
      printf("entering callback\n");
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}



int main( int argc, char *argv[] )  {    

      struct nfq_handle *h;
      struct nfq_q_handle *qh;
      struct nfnl_handle *nh;
      int fd;
      int rv;
      char buf[4096] __attribute__ ((aligned));

      if( argc == 5 ) {
      	printf("The argument supplied is %s\n", argv[1]);
    	matchip=argv[1];
    	matchPort=atoi(argv[2]);
    	matchCount=atoi(argv[3]);
    	matchStr=argv[4];

   	//printf("Ip %s\n", matchip);
   	//printf("Port %d\n", matchPort);
   	//printf("Counter %d\n", matchCount);
   	//printf("String %s\n", matchStr);
      }
      else {
      	printf("Missing Argument! Provide following tuple (ip,port,counter,string)\n");
	return 0;
      }

      printf("opening library handle\n");
      h = nfq_open();
      if (!h) {
            fprintf(stderr, "error during nfq_open()\n");
            exit(1);
      }

      printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
      if (nfq_unbind_pf(h, AF_INET) < 0) {
            fprintf(stderr, "error during nfq_unbind_pf()\n");
            exit(1);
      }

      printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
      if (nfq_bind_pf(h, AF_INET) < 0) {
            fprintf(stderr, "error during nfq_bind_pf()\n");
            exit(1);
      }

      printf("binding this socket to queue '0'\n");
      qh = nfq_create_queue(h,  0, &cb, NULL);
      if (!qh) {
            fprintf(stderr, "error during nfq_create_queue()\n");
            exit(1);
      }

      printf("setting copy_packet mode\n");
      if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
            fprintf(stderr, "can't set packet_copy mode\n");
            exit(1);
      }

      fd = nfq_fd(h);

      while (matchCount>0 && (rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
            printf("pkt received\n");
	    printf("======%d=====\n", matchCount);
            nfq_handle_packet(h, buf, rv);
	    matchCount=matchCount-1;
	    

      }

      printf("unbinding from queue 0\n");
      nfq_destroy_queue(qh);

#ifdef INSANE
      /* normally, applications SHOULD NOT issue this command, since
       * it detaches other programs/sockets from AF_INET, too ! */
      printf("unbinding from AF_INET\n");
      nfq_unbind_pf(h, AF_INET);
#endif

      printf("closing library handle\n");
      nfq_close(h);

      exit(0);
}

