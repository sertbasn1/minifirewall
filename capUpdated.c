#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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
int termination=0;
FILE * fp;
int payload_size;



int subStringSearch(char * Str,char * subStr){
    //printf(" %s and %s is compared \n",Str, subStr);
    int total=0;
    while ( (Str=strstr(Str,subStr)) != NULL ){
        total++;
        Str++;
    }
    return total;
}


/* returns packet id */
static u_int32_t examine_pkt (struct nfq_data *tb)
{
    int id = 0;
    int occurence=0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;
    char *data;
    char *tuser_data,*uuser_data;
    unsigned short src_port;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
        id = ntohl(ph->packet_id);
    }

    ret = nfq_get_payload(tb, (unsigned char**)&data);
    if (ret >= 0){//payload_len is not eq 0

    //parssing the packet fields
    struct iphdr * ip_info = (struct iphdr *)data;
  
    //TCP Part
    if(ip_info->protocol == IPPROTO_TCP) {
        struct tcphdr * tcp_info = (struct tcphdr *)(data + sizeof(*ip_info));
        src_port = ntohs(tcp_info->source);
        //TCP header size
        int tcph_len = tcp_info->doff*4;
        //get tcp payload
        tuser_data = (char *)tcp_info + tcph_len;
        payload_size = ntohs(ip_info->tot_len)-sizeof(*ip_info)-tcph_len;
        
        //checking source port and source ip adresses
        if((ip_info->saddr == inet_addr(matchip)) && (src_port==matchPort)){
            printf("Packet with srcIP %s and srcPort %d is captured\n",matchip, matchPort);
            char pstring[payload_size];
            strncpy(pstring,tuser_data, payload_size);
            occurence=subStringSearch(pstring,matchStr);
            
            if (occurence== 0) //matchStr is not found in the payload
                printf("No match with the payload\n");
            else{
                printf("TCP Packet %d satisfying criteria\n", termination+1);
                //write to file and update counter
                fp = fopen ("output.txt","a");
                /* write text into the file stream*/
                fprintf (fp, "payload:");
                printf("Payload is: ");
                int c = 0;
                
                while (c!= payload_size) {
                    if (tuser_data[c] > 31 && tuser_data[c] < 127)
                        {printf("%c", tuser_data[c]);
                         fprintf(fp,"%c",tuser_data[c]); }
                    else
                        {printf("%s","." );
                        fprintf(fp,"%s","."); }
                    c=c+1;
                }
                
                    printf("\nOccurence of '%s' is: %d\n",matchStr,occurence);
                    fprintf (fp, "\nappearances: %d\n",occurence);
                    fprintf (fp, "--- --- --- \n");

                    /* close the file*/
                    fclose (fp);
                    termination=termination+1;
               }
            }
        }
    
    //UDP Part
    else if(ip_info->protocol == IPPROTO_UDP){
        struct udphdr * udp_info = (struct udphdr*)(data + sizeof(*ip_info));
        src_port = ntohs(udp_info->source);

         //UDP header size
         int udph_len = sizeof(struct udphdr);
         //get udp payload
         uuser_data = (char *) udp_info + udph_len;
         payload_size = ntohs(udp_info->len) - udph_len;
    
        //checking source port and source ip adresses
        if((ip_info->saddr == inet_addr(matchip)) && (src_port==matchPort)){
            printf("Packet with srcIP %s and srcPort %d is captured\n",matchip, matchPort);

            char pstring[payload_size];
            strncpy(pstring,uuser_data, payload_size);
            occurence=subStringSearch(pstring,matchStr);

            if (occurence==0){ //matchStr is not found in the payload
                printf("No match with the payload\n");
            }
            else{
                printf("UDP Packet %d satisfying criteria\n", termination+1);
                //write to file and update counter
                fp = fopen ("output.txt","a");
                /* write text into the file stream*/
                fprintf (fp, "payload:");
                printf("Payload is: ");
                int c = 0;

                while (c!= payload_size) {
                    if (tuser_data[c] > 31 && tuser_data[c] < 127)
                        {printf("%c", uuser_data[c]);
                        fprintf(fp,"%c",uuser_data[c]); }
                    else
                        {printf("%s","." );
                        fprintf(fp,"%s","."); }
                    c=c+1;
                }
                
                printf("\nOccurence of '%s' is: %d",matchStr,occurence);
                fprintf (fp, "\nappearances: %d\n",occurence);
                fprintf (fp, "--- --- --- \n");
                
                /* close the file*/
                fclose (fp);
                termination=termination+1;
            }
        }
    }
  }
    fputc('\n', stdout);
    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
    
    u_int32_t id = examine_pkt(nfa);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main( int argc, char *argv[] )  {    

      struct nfq_handle *h;
      struct nfq_q_handle *qh;

      int fd;
      int rv;
      char buf[4096] __attribute__ ((aligned));

      if( argc == 5 ) {
          matchip=argv[1];
          matchPort=atoi(argv[2]);
          matchCount=atoi(argv[3]);
          matchStr=argv[4];
      }
      else {
          printf("Missing Argument! Provide following tuple (ip,port,counter,string)\n");
          return EXIT_FAILURE;
      }

    int status = system("sudo iptables -A INPUT -i eth1 -j NFQUEUE --queue-num 0");
    if( status != 0 ) {
        printf("Error occured creating flow rules via iptables!\n");
        return EXIT_FAILURE;
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

    while (termination<matchCount && (rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        printf("--- --- --- ");
        printf("pkt received\n");
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    status = system("sudo iptables --flush");
    if( status == 0 ) {
        printf("Flow rule is removed..\n");
    }

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



