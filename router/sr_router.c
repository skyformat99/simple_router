/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);

	struct sr_ethernet_hdr * ethernet_hdr = (struct sr_ethernet_hdr *)packet;
	if(len < sizeof(struct sr_ethernet_hdr)){
	    printf("The length of the received packet is incorrect");
	    return;
  	}

  	/*check if it is a ARP request*/
  	if(ethernet_hdr -> ether_type ==  htons(ethertype_arp)){
  		printf("Receive ARP packet\n");
		print_hdrs(packet, len);
		router_handle_arp(sr, packet, len, interface);
		return;
	}
	/* Receive IP */
    else if (ethernet_hdr -> ether_type == htons(ethertype_ip)) {
    	printf("Receive IP packet\n");
		print_hdrs(packet, len);
		router_handle_ip(sr, packet, len, interface);
		return;
    }
}

void router_handle_arp(struct sr_instance *sr,uint8_t *packet, unsigned int len, char *interface){

	if(len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)){
	    printf("The length of the received arp packet is incorrect");
	    return;
  	}

  	struct sr_arp_hdr * arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  	/*arp request*/
	if (arp_hdr -> ar_op == htons(arp_op_request)){
		uint8_t * eth_packet = (uint8_t *)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
		struct sr_ethernet_hdr * reply_ethernet_hdr = (struct sr_ethernet_hdr *)(eth_packet);
  		struct sr_arp_hdr * reply_arp_hdr = (struct sr_arp_hdr *)(eth_packet + sizeof(struct sr_ethernet_hdr));


  		struct sr_if * sr_interface = sr_get_interface(sr,interface);


		reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
		reply_arp_hdr->ar_pln = arp_hdr->ar_pln;
  		reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
		reply_arp_hdr->ar_pro = arp_hdr->ar_pro;		       
		reply_arp_hdr->ar_op = htons(arp_op_reply);
    	reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
    	reply_arp_hdr->ar_sip = sr_interface->ip;
    	memcpy(reply_arp_hdr -> ar_tha, arp_hdr -> ar_sha,ETHER_ADDR_LEN);
    	memcpy(reply_arp_hdr -> ar_sha, sr_interface -> addr,ETHER_ADDR_LEN);

   		
  		memcpy(reply_ethernet_hdr -> ether_shost,sr_interface -> addr,ETHER_ADDR_LEN);
        memcpy(reply_ethernet_hdr -> ether_dhost,arp_hdr -> ar_sha,ETHER_ADDR_LEN);
  		reply_ethernet_hdr -> ether_type = htons(ethertype_arp);

  		printf("Router send ARP reply\n\n");
		print_hdrs(eth_packet, len);
		sr_send_packet(sr, eth_packet, len, interface);

    	free(eth_packet);
    	return;
    }
    else if (arp_hdr -> ar_op == htons(arp_op_reply)){
    	struct sr_arpreq * lookup_arpreq = sr_arpcache_insert(&sr -> cache,arp_hdr ->ar_sha,arp_hdr -> ar_sip);
    	if(lookup_arpreq != NULL){
    		struct sr_packet * curr_packet = lookup_arpreq -> packets;

    		while (curr_packet != NULL) {
    			struct sr_ethernet_hdr * curr_ethernet_hdr = (struct sr_ethernet_hdr *)curr_packet -> buf;
    			struct sr_if * interface = sr_get_interface(sr, curr_packet -> iface);
    			memcpy(curr_ethernet_hdr ->ether_shost,interface->addr,ETHER_ADDR_LEN);
      			memcpy(curr_ethernet_hdr -> ether_dhost,arp_hdr ->ar_sha,ETHER_ADDR_LEN);
				sr_send_packet(sr, curr_packet->buf, curr_packet->len, curr_packet->iface);
				curr_packet = curr_packet -> next;
			}
			sr_arpreq_destroy(&sr->cache, lookup_arpreq);
			return;
		}
	}
}

void router_handle_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
	struct sr_ip_hdr * ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
	if(len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)){
	    printf("The length of the received ip packet is incorrect");
	    return;
  	}

  	/*check the checksum for the ip header*/
    uint16_t ip_hdr_sum = ip_hdr ->ip_sum;
    ip_hdr -> ip_sum = 0;
    if(ip_hdr_sum != cksum(ip_hdr,sizeof(struct sr_ip_hdr))){
      printf("The checksum is not correct: %u\n", cksum(ip_hdr,sizeof(struct sr_ip_hdr))); 
      return;
    }
    ip_hdr -> ip_sum = ip_hdr_sum;

	if (!ip_in_interfaces(sr, ip_hdr->ip_dst)) {
		ip_hdr->ip_ttl--;
		if(ip_hdr -> ip_ttl == 0){
			send_icmp_eleven_packet(sr, packet, interface, len);
    	}
    	ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

		struct sr_rt *rt = lpm(sr , ip_hdr -> ip_dst);
		if(rt){
			/* Outgoing interface*/
			struct sr_if *sr_interface = sr_get_interface(sr, rt->interface);
			struct  sr_arpentry * arpentry = sr_arpcache_lookup(&sr->cache ,ip_hdr -> ip_dst);
			/*not found*/
			if (!arpentry) {
				/* Add to the arp queue */
				handle_arpreq(sr,sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, sr_interface->name));
   			 	return;
			}
			else{
			 	struct sr_ethernet_hdr * ethernet_hdr = (struct sr_ethernet_hdr *)packet;
			 	/*modify the MAC address in the ethernet header*/
    			memcpy(ethernet_hdr -> ether_shost, sr_interface -> addr, ETHER_ADDR_LEN);
    			memcpy(ethernet_hdr -> ether_dhost, arpentry -> mac, ETHER_ADDR_LEN);
    			sr_send_packet(sr, packet, len, sr_interface -> name);
    			return;
    		}
		}
		else{
			send_icmp_three_packet(sr,packet, interface, len, sr_icmp_type_three, sr_icmp_code_zero);
			return;
		}
	}
	else{
		if(ip_hdr->ip_p == ip_protocol_icmp){
		 	struct sr_icmp_hdr * icmp_hdr = ((struct sr_icmp_hdr *)(packet + sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr)));
		 	if (icmp_hdr->icmp_type == (uint8_t)8) {
				send_icmp_echo_packet(sr, packet, interface,len, sr_icmp_type_zero, sr_icmp_code_zero);
			}
		}
		else if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp){
        		/* Send ICMP port unreachable */
        		send_icmp_three_packet(sr,packet, interface, len, sr_icmp_type_three, sr_icmp_code_three);
    	}
    	return;
	}
}

void send_icmp_echo_packet(struct sr_instance* sr, uint8_t *packet, char* interface, unsigned int len, int type, int code){

	struct sr_ethernet_hdr *received_ethernet_hdr = (struct sr_ethernet_hdr *)packet;
	struct sr_ip_hdr *received_ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
	struct sr_if * sr_interface = sr_get_interface(sr, interface);
	uint8_t *packet_to_send = ((uint8_t *)malloc(len));
	struct sr_ethernet_hdr *reply_ethernet_hdr = (struct sr_ethernet_hdr *) packet_to_send;
	struct sr_ip_hdr *reply_ip_hdr = (struct sr_ip_hdr *) (packet_to_send + sizeof(struct sr_ethernet_hdr));
	struct sr_icmp_hdr * reply_icmp_hdr = ((struct sr_icmp_hdr *)(packet_to_send + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)));



	/*construct icmp hdr*/
	memcpy(packet_to_send, packet, len);
	reply_icmp_hdr -> icmp_type = (uint8_t) type;
	reply_icmp_hdr -> icmp_code = (uint8_t) code;
	reply_icmp_hdr -> icmp_sum = (uint16_t) 0;
	reply_icmp_hdr -> icmp_sum = cksum(reply_icmp_hdr,len - sizeof(sr_ethernet_hdr_t) - sizeof(struct sr_ip_hdr));

	/*construct ip hdr*/	
	reply_ip_hdr -> ip_ttl = INIT_TTL;
	reply_ip_hdr -> ip_src = received_ip_hdr->ip_dst;
	reply_ip_hdr -> ip_dst = received_ip_hdr->ip_src;
	reply_ip_hdr -> ip_id = 0;
	reply_ip_hdr -> ip_sum = 0;
	reply_ip_hdr -> ip_sum = cksum(reply_ip_hdr, sizeof(struct sr_ip_hdr));

  	int i;
	for(i = 0; i < ETHER_ADDR_LEN; i++){
    	reply_ethernet_hdr -> ether_dhost[i] = received_ethernet_hdr -> ether_shost[i];
    	reply_ethernet_hdr -> ether_shost[i] = sr_interface -> addr[i];
  	}
  	reply_ethernet_hdr -> ether_type = htons(ethertype_ip);
  	printf("\n\nsending echo icmp\n\n");
  	sr_send_packet(sr,packet_to_send,len, interface);
  	free(packet_to_send);
}


void send_icmp_three_packet(struct sr_instance* sr, uint8_t *packet, char* interface, unsigned int len, int type, int code){

	struct sr_ethernet_hdr * received_ethernet_hdr = (struct sr_ethernet_hdr *)(packet);
	struct sr_ip_hdr *received_ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
	
	uint8_t * packet_to_send = ((uint8_t *)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr)));
	struct sr_ethernet_hdr * reply_ethernet_hdr = (struct sr_ethernet_hdr *) packet_to_send;
	struct sr_ip_hdr *reply_ip_hdr = (struct sr_ip_hdr *) (packet_to_send + sizeof(struct sr_ethernet_hdr));
	struct sr_icmp_t3_hdr * reply_icmp_t3_hdr = (struct sr_icmp_t3_hdr *) (packet_to_send + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

	struct sr_if * sr_interface = sr_get_interface(sr, interface);


	reply_icmp_t3_hdr -> icmp_type = (uint8_t)type;
	reply_icmp_t3_hdr -> unused = 0;
	reply_icmp_t3_hdr -> icmp_code = (uint8_t)code;
	reply_icmp_t3_hdr -> next_mtu = 0;
	memcpy(reply_icmp_t3_hdr -> data, received_ip_hdr, ICMP_DATA_SIZE);
	reply_icmp_t3_hdr -> icmp_sum = 0;
	reply_icmp_t3_hdr -> icmp_sum = cksum(reply_icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));


	/*construct ip hdr*/

	reply_ip_hdr -> ip_hl = received_ip_hdr -> ip_hl;
	reply_ip_hdr -> ip_v = received_ip_hdr -> ip_v;
	reply_ip_hdr -> ip_tos = received_ip_hdr -> ip_tos;
	reply_ip_hdr -> ip_off = received_ip_hdr -> ip_off;	
	reply_ip_hdr -> ip_ttl = INIT_TTL;
	reply_ip_hdr -> ip_p = ip_protocol_icmp;
	reply_ip_hdr -> ip_sum = 0;

	if (code == sr_icmp_code_zero || code == sr_icmp_code_one) {
		reply_ip_hdr -> ip_src = sr_interface -> ip;
	}
	else {
		reply_ip_hdr -> ip_src =  received_ip_hdr -> ip_dst;
	}

	reply_ip_hdr -> ip_dst = received_ip_hdr -> ip_src;
	reply_ip_hdr -> ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
	reply_ip_hdr -> ip_id = 0;
	reply_ip_hdr -> ip_sum = cksum(reply_ip_hdr, sizeof(struct sr_ip_hdr));

	memcpy(reply_ethernet_hdr -> ether_shost, sr_interface -> addr, ETHER_ADDR_LEN); 
	memcpy(reply_ethernet_hdr -> ether_dhost, received_ethernet_hdr -> ether_shost, ETHER_ADDR_LEN); 
	
  	reply_ethernet_hdr -> ether_type = htons(ethertype_ip);

  	printf("\n\nsending type 3 icmp\n\n");
	print_hdrs(packet_to_send, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
  	sr_send_packet(sr,packet_to_send,sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof (struct sr_icmp_t3_hdr), interface);
  	free(packet_to_send);
}

void send_icmp_eleven_packet(struct sr_instance* sr, uint8_t *packet, char* interface,unsigned int len){

	struct sr_ip_hdr * received_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
	uint8_t *reply_packet = (uint8_t *)malloc(sizeof(struct sr_icmp_t11_hdr) + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
	memset(reply_packet,0, sizeof(struct sr_icmp_t11_hdr) + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
	struct sr_ethernet_hdr * reply_ethernet_hdr = (struct sr_ethernet_hdr *) reply_packet;
	struct sr_ip_hdr * reply_ip_hdr = (struct sr_ip_hdr *) (reply_packet + sizeof(struct sr_ethernet_hdr));
	struct sr_icmp_t11_hdr * reply_icmp_t11_hdr = (struct sr_icmp_t11_hdr *) (reply_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

	struct sr_if *sr_interface = sr_get_interface(sr, interface);

	/*construct icmp t11 hdr*/
	reply_icmp_t11_hdr->icmp_type = (uint8_t) 11;
	reply_icmp_t11_hdr->unused = (uint32_t) 0;
	reply_icmp_t11_hdr->icmp_sum = (uint16_t) 0;
	reply_icmp_t11_hdr->icmp_code = (uint8_t) 0;
	memcpy(reply_icmp_t11_hdr->data, received_ip_hdr, ICMP_DATA_SIZE);
	reply_icmp_t11_hdr->icmp_sum = cksum(reply_icmp_t11_hdr, sizeof(struct sr_icmp_t11_hdr));

	/*construct ip hdr*/

	reply_ip_hdr->ip_hl = received_ip_hdr->ip_hl;
	reply_ip_hdr->ip_v = received_ip_hdr->ip_v;
	reply_ip_hdr->ip_tos = received_ip_hdr->ip_tos;
	reply_ip_hdr->ip_off = received_ip_hdr->ip_off;
	reply_ip_hdr->ip_ttl = INIT_TTL;
	reply_ip_hdr->ip_p = ip_protocol_icmp;
	reply_ip_hdr->ip_src = sr_interface->ip;
	reply_ip_hdr->ip_dst = received_ip_hdr->ip_src;
	reply_ip_hdr->ip_len = sizeof(sr_ip_hdr_t) + sizeof(struct sr_icmp_t11_hdr);
	reply_ip_hdr->ip_id = 0;
	reply_ip_hdr->ip_sum = 0x0;
	reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(struct sr_ip_hdr));

	/*construct etnet hdr*/
	memcpy(reply_ethernet_hdr->ether_shost, sr_interface->addr, ETHER_ADDR_LEN); 
	memcpy(reply_ethernet_hdr->ether_dhost, reply_ethernet_hdr->ether_shost, ETHER_ADDR_LEN); 
	reply_ethernet_hdr->ether_type = htons(ethertype_ip);

	printf("\nrouter sending t11 icmp\n");
	print_hdr_ip(reply_packet);
	sr_send_packet(sr, reply_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t11_hdr), interface);
	free(reply_packet);

} 

int ip_in_interfaces(struct sr_instance * sr, uint32_t ip_dest){
  struct sr_if* sr_interface = sr->if_list;

  while(sr_interface){
    if (sr_interface->ip == ip_dest) {
      return 1;   
    }
    sr_interface = sr_interface->next;
  }
  return 0;
}

struct sr_rt* lpm(struct sr_instance *sr, uint32_t target_ip){
   /* Find match interface in routing table LPM */
    struct sr_rt* curr_rt_entry = sr->routing_table;
    struct sr_rt* result = NULL;
    while(curr_rt_entry != NULL)
    {
        /* check for prefix match */
        if ((ntohl(curr_rt_entry->dest.s_addr) & ntohl(curr_rt_entry->mask.s_addr))
          == (ntohl(target_ip) & ntohl(curr_rt_entry->mask.s_addr)) &&
      (result == NULL || curr_rt_entry->mask.s_addr > result->mask.s_addr))
        {
          result = curr_rt_entry;
        }
        curr_rt_entry = curr_rt_entry->next;
    }
    return result;
} 