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

  /* fill in code here */
  //sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
  uint16_t type = ethertype(packet);
  if (type == ethertype_arp) {
    fprintf(stderr, "It's an ARP packet!\n");
    //handle_arp_packet(sr, packet, len, in_iface_name);
    handle_arp_packet(sr, packet, len, interface);
  }
  else if (type == ethertype_ip) {
    fprintf(stderr, "It's an IP packet!\n");
    handle_ip_packet(sr, packet, len, interface);
  }

}/* end sr_ForwardPacket */

//handle arp request is basically for getting the router interface so that packet can send from the host to
//router and 
void handle_arp_packet(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){
  //interface of the router that the packet is sent to
  //sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  // sr_if* receive_interface= sr_get_interface(sr, interface);
  uint16_t choice = ntohs(arp_hdr->ar_op);
  if (choice == arp_op_request){
    printf("arp_request\n");
    handle_arp_request(sr, packet,len, interface);
  }
  else{
    printf("arp_reply\n");
    handle_arp_reply(sr, packet,len, interface);
  }
}
//basically for transmitting the packets between routers or when the hosts talk to the router
void handle_arp_request(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){
  //get the information from the old packet sent
  sr_ethernet_hdr_t* a_eth_hdr = (sr_ethernet_hdr_t*) packet;
  sr_arp_hdr_t* a_arp_hdr = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  //create new arp request packet
  uint8_t* arp_request = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t* b_eth_hdr = (sr_ethernet_hdr_t*) arp_request;
  sr_arp_hdr_t* b_arp_hdr = (sr_arp_hdr_t*) (arp_request + sizeof(sr_ethernet_hdr_t));
  //assign the correct value for each field in the header
  struct sr_if* curr_interface= sr_get_interface(sr, interface);
  fprintf(stderr, "\ttype: %d\n", ntohs(a_eth_hdr->ether_type));
  b_eth_hdr ->ether_type = a_eth_hdr ->ether_type;
  memcpy(b_eth_hdr->ether_dhost, a_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(b_eth_hdr->ether_shost, curr_interface->addr, ETHER_ADDR_LEN);
  b_arp_hdr->ar_hrd = a_arp_hdr->ar_hrd;
  b_arp_hdr->ar_pro = a_arp_hdr->ar_pro;
  b_arp_hdr->ar_hln = a_arp_hdr->ar_hln;
  b_arp_hdr->ar_pln = a_arp_hdr->ar_pln;
  b_arp_hdr->ar_op = htons(arp_op_reply); //change it to reply type
  b_arp_hdr->ar_sip = curr_interface->ip; //current interface IP of the router
  b_arp_hdr->ar_tip = a_arp_hdr->ar_sip;//change to the IP address of the source 
  memcpy(b_arp_hdr->ar_sha, curr_interface->addr, ETHER_ADDR_LEN); //memcpy since it is an arry
  memcpy(b_arp_hdr->ar_tha, a_arp_hdr->ar_sha, ETHER_ADDR_LEN);
  //send the packet back once it knows the mac address
  printf("in arp!!!!!!!!!!!!!!!!!!!!\n");
  sr_send_packet(sr, arp_request, len, curr_interface -> name);
  printf("in arp!!!!!!!!!!!!!!!!!!!!\n");

}
//send the macaddress of the destination back
void handle_arp_reply(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  //we get the linked list corresponding to this IP address and the store the mac address mapping with ar_sip to the mac address
  struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
                                            
  struct sr_packet* temp;
  printf("hello\n");
  if (req != NULL) { // send reaming packet in the request queue corresponding to that(if it finds that)
      for (temp = req->packets; temp != NULL; temp = temp->next) {
        printf("This is wrong");
        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(temp -> buf);
        struct sr_if* curr_interface= sr_get_interface(sr, interface);
        memcpy(eth_hdr->ether_dhost, arp_hdr ->ar_sha, ETHER_ADDR_LEN);//destination host to be the mac address
        memcpy(eth_hdr->ether_shost, curr_interface->addr, ETHER_ADDR_LEN);//source host to be the interface address
        printf("what!!!!!!!!!!!!!!!!!!!!");
        sr_send_packet(sr, temp->buf, temp->len, req->packets->iface);
        printf("what!!!!!!!!!!!!!!!!!!!!");
        
        //fprintf(stderr, "Forwarding packet from interface %s:\n", pkt->out_iface);
            //print_hdrs(pkt->buf, pkt->len);
      }
      sr_arpreq_destroy(&sr->cache, req);//after it sends it, destroy it
    }
}

void handle_ip_packet(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){
  //check for the TTL and send the ICMP Packet
  
  //send Time exceeded (type 11, code 0) ICMP Packet
  //check if it is for the router or for the host
  print_hdrs(packet, len);
  sr_ip_hdr_t* packet_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  int k = 0;//if it is for this router
  for (struct sr_if* interface = sr->if_list; interface != NULL; interface = interface->next){
      if (interface ->ip == packet_header ->ip_dst){
          k = 1;
      }
  }
  //when it is destined for me//then send the echo reply
  if (k == 1){
    //if it is echo request, then send the echo reply
    printf("This is for me!!\n");
    sr_icmp_t08_hdr_t* icmp_hdr = (sr_icmp_t08_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    printf("icmp_hdr type: %u\n", icmp_hdr ->icmp_type);
    if (icmp_hdr ->icmp_type == 0x08){
      
      send_echo_reply(sr,packet,len,interface);
    }
    //send ICMP packet
    //handle icmp packets
    //if get the echo request then send the echo reply
        //else just say receives the echo reply
        //question host automatically constructs the echo request? Does Router construct the echo request? Do I need to send the echo request 
        //from the router myself?  
  }
  else{//in this case we need to find the next hop and forward the packet
  //check the routing table to see if the dst_id is in there
    struct sr_if* curr_interface;
    struct sr_rt* match = sr->routing_table;
    int is_in_rt_table = 0;
    while(match){
        uint32_t dist =  packet_header->ip_dst;
        if(dist == match->dest.s_addr){
          curr_interface = sr_get_interface(sr, match->interface);
          is_in_rt_table = 1;
          break;
        }
      match = match->next;
    }
    //if it is forward the packet//do not use cache at all, thus always store in the queue when the new packet come
    //and send the arp request to get the mac address
    if (is_in_rt_table == 1){
      printf("it is for me ready to put it in the queue");
      struct sr_arpreq* arp_request = sr_arpcache_queuereq(&sr->cache, packet_header->ip_dst, packet, len, curr_interface->name);
      handle_arpreq(sr,arp_request);
    }
    else{//otherwise, send ICMP packet back
    //ICMP PACKET Destination net unreachable (type 3, code 0):can not find it in the routing table
      send_ICMP3_TYPE0(sr, packet,len, interface);
    }

  }
}
//still need revision
void send_echo_reply(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){
    printf("echo reply1:\n");
    print_hdrs(packet,len);
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t08_hdr_t* icmp_hdr = (sr_icmp_t08_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    sr_print_routing_table(sr);
    //in thr routing table, find the eth that I should send from
    struct sr_if* curr_interface;
    struct sr_rt* match = sr->routing_table;
    while(match){
        uint32_t dist =  ip_hdr->ip_src;
        if(dist == match->dest.s_addr){
          printf("AAAAA\n");
          curr_interface = sr_get_interface(sr, match->interface);
          break;
        }
      match = match->next;
    }
    memcpy(eth_hdr->ether_dhost, eth_hdr ->ether_shost, ETHER_ADDR_LEN);//destination host to be the mac address
    memcpy(eth_hdr->ether_shost, curr_interface->addr, ETHER_ADDR_LEN);//source host to be the interface address
    uint32_t temp = ip_hdr ->ip_dst;
    ip_hdr -> ip_dst = ip_hdr -> ip_src;
    ip_hdr -> ip_src = temp;
    icmp_hdr -> icmp_type = 0x00;
    
    printf("echo reply:\n");
    print_hdrs(packet,len);
    sr_send_packet(sr, packet, len, curr_interface->name);
}

void send_ICMP3_TYPE0(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){
  
}

