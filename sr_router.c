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
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if (ntohs(arp_hdr->ar_op) == arp_op_request){
      //printf("arp_request\n");
      handle_arp_request(sr, packet,len, interface);
    }
    else{
    // printf("arp_reply\n");
      handle_arp_reply(sr, packet,len, interface);
    }
  }
  else if (type == ethertype_ip) {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)){
      return;
    }
    handle_ip_packet(sr, packet, len, interface);
  }

}/* end sr_ForwardPacket */


//basically for transmitting the packets between routers or when the hosts talk to the ro
void handle_arp_request(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){
  sr_ethernet_hdr_t* a_eth_hdr = (sr_ethernet_hdr_t*) packet;
  sr_arp_hdr_t* a_arp_hdr = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  uint8_t* arp_request = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t* b_eth_hdr = (sr_ethernet_hdr_t*) arp_request;
  sr_arp_hdr_t* b_arp_hdr = (sr_arp_hdr_t*) (arp_request + sizeof(sr_ethernet_hdr_t));
  //assign the correct value for each field in the header
  struct sr_if* curr_interface= sr_get_interface(sr, interface);
  b_eth_hdr ->ether_type = a_eth_hdr ->ether_type;
  memcpy(b_eth_hdr->ether_dhost, a_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(b_eth_hdr->ether_shost, curr_interface->addr, ETHER_ADDR_LEN);
  b_arp_hdr->ar_hrd = a_arp_hdr->ar_hrd;
  b_arp_hdr->ar_pro = a_arp_hdr->ar_pro;
  b_arp_hdr->ar_hln = a_arp_hdr->ar_hln;
  b_arp_hdr->ar_pln = a_arp_hdr->ar_pln;
  b_arp_hdr->ar_op = htons(arp_op_reply); //change it to reply type
  memcpy(b_arp_hdr->ar_sha, curr_interface->addr, ETHER_ADDR_LEN); //memcpy since it is an arry
  b_arp_hdr->ar_sip = curr_interface->ip; //current interface IP of the router
  
  memcpy(b_arp_hdr->ar_tha, a_arp_hdr->ar_sha, ETHER_ADDR_LEN);
  b_arp_hdr->ar_tip = a_arp_hdr->ar_sip;//change to the IP address of the source 
  
  //send the packet back once it knows the mac address
  //printf("in arp!!!!!!!!!!!!!!!!!!!!\n");
  sr_send_packet(sr, arp_request, len, curr_interface -> name);
  //printf("in arp!!!!!!!!!!!!!!!!!!!!\n");

}
/* the hint from sr_arpcache.c
# When servicing an arp reply that gives us an IP->MAC mapping
   req = arpcache_insert(ip, mac)

   if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)

   --*/
//send the macaddress of the destination back
void handle_arp_reply(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  //we get the linked list corresponding to this IP address and the store the mac address mapping with ar_sip to the mac address
  struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
                                            
  struct sr_packet* temp;
  //printf("hello\n");
  if (req != NULL) { // send reaming packet in the request queue corresponding to that(if it finds that)
      for (temp = req->packets; temp != NULL; temp = temp->next) {
        //printf("This is wrong");
        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(temp -> buf);
        sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t*)(temp -> buf+sizeof(sr_ethernet_hdr_t));
        struct sr_if* curr_interface= sr_get_interface(sr, interface);
        eth_hdr->ether_type = eth_hdr->ether_type;
        memcpy(eth_hdr->ether_dhost, arp_hdr ->ar_sha, ETHER_ADDR_LEN);//destination host to be the mac address
        memcpy(eth_hdr->ether_shost, curr_interface->addr, ETHER_ADDR_LEN);//source host to be the interface address
        
        new_ip_hdr->ip_tos = new_ip_hdr->ip_tos;
        new_ip_hdr->ip_len = new_ip_hdr->ip_len;
        new_ip_hdr->ip_id = new_ip_hdr->ip_id;
        new_ip_hdr->ip_off = new_ip_hdr->ip_off;
        new_ip_hdr->ip_ttl = new_ip_hdr->ip_ttl;
        new_ip_hdr->ip_p = new_ip_hdr->ip_p;
        new_ip_hdr -> ip_src = new_ip_hdr -> ip_src;
        new_ip_hdr -> ip_dst = new_ip_hdr -> ip_dst;
       
        new_ip_hdr->ip_sum = 0x0000;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

        //printf("what!!!!!!!!!!!!!!!!!!!!");
        sr_send_packet(sr, temp->buf, temp->len, req->packets->iface);
        //printf("what!!!!!!!!!!!!!!!!!!!!");
        
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
  uint16_t temp_sum = packet_header->ip_sum;
  packet_header->ip_sum = 0x0000;
 // printf("wantfeqf  2ed 2dasda\n");
 // printf("%hu\n", temp_sum);
  //printf("%hu\n", cksum(packet_header, sizeof(sr_ip_hdr_t)));
  if(temp_sum != cksum(packet_header, sizeof(sr_ip_hdr_t)))
  {  
    //printf(" ip packet check sum is not correct\n");
    return;
  }
  else{
    //printf("aqw\n");
    packet_header->ip_sum = temp_sum;
  }
    
  int k = 0;//if it is for this router
  for (struct sr_if* interface = sr->if_list; interface != NULL; interface = interface->next){
      if (interface ->ip == packet_header ->ip_dst){
          k = 1;
      }
  }
  //when it is destined for me//then send the echo reply
  if (k == 1){
    //if it is echo request, then send the echo reply
    //printf("This is for me!!\n");
    sr_icmp_t08_hdr_t* icmp_hdr = (sr_icmp_t08_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    //printf("icmp_hdr type: %u\n", icmp_hdr ->icmp_type);
    if (packet_header -> ip_p == ip_protocol_icmp){
      if (icmp_hdr ->icmp_type == 0x08){
      
        send_echo_reply(sr,packet,len,interface);
      }
    }
    else if (packet_header -> ip_p == 0x06 || packet_header -> ip_p == 17){
      //printf("echo reply\n");
      //print_hdrs(packet,len);
      //send unreachable
      send_ICMP3_TYPE3(sr, packet, len, interface);
    }
    else{
      //printf("echo reply\n");
      //print_hdrs(packet,len);
      return;
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
    packet_header->ip_ttl = packet_header->ip_ttl - 1;
    //printf("ttl%u:\n",packet_header->ip_ttl);
    if (packet_header->ip_ttl == 0){
      //printf(" Time out!!\n");
      packet_header->ip_sum = 0x0000;
      packet_header->ip_sum = cksum(packet_header, sizeof(sr_ip_hdr_t));
      send_ICMP11(sr, packet, len,interface);
      return;
    }
    packet_header->ip_sum = 0x0000;
    packet_header->ip_sum = cksum(packet_header, sizeof(sr_ip_hdr_t));
    struct sr_if* curr_interface;
    struct sr_rt* match = sr->routing_table;
    int is_in_rt_table = 0;
    while(match){
        uint32_t dist =  packet_header->ip_dst & match->mask.s_addr;
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
      //printf("it is for me ready to put it in the queue");
      

      //check if it is in the arp entry
      struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, match->gw.s_addr);
      ////////////////////////////////////////////////////////////////////////WHAT I ADD to Project 2b
      if (arp_entry){
        //printf("it is in the arp entry\n");
        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, curr_interface->addr, ETHER_ADDR_LEN);
        //printf("forward the packet\n");
        sr_send_packet(sr, packet, len, curr_interface->name);
      }
      else{
        struct sr_arpreq* arp_request = sr_arpcache_queuereq(&sr->cache, match->gw.s_addr, packet, len, curr_interface->name);
      handle_arpreq(sr,arp_request);
      }
      
    }
    else{//otherwise, send ICMP packet back
    //ICMP PACKET Destination net unreachable (type 3, code 0):can not find it in the routing table
    //printf("WOWOWOWOWOWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW");
      send_ICMP3_TYPE0(sr, packet,0, interface);
    }

  }
}
//still need revision
void send_echo_reply(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){
   // printf("echo reply1:\n");
    //print_hdrs(packet,len);
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t08_hdr_t* icmp_hdr = (sr_icmp_t08_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    uint16_t temp_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0x0000;
 // printf("%hu\n", temp_sum);
  //printf("%hu\n", cksum(ip_hdr, sizeof(sr_ip_hdr_t)));
  if(temp_sum != cksum(ip_hdr, sizeof(sr_ip_hdr_t))){  
    //printf(" wrong\n");
    return;
  }
  else{
    //printf("WWWW1111\n");
    ip_hdr->ip_sum = temp_sum;
  }
    sr_print_routing_table(sr);
    //in thr routing table, find the eth that I should send from
    struct sr_if* curr_interface;
    struct sr_rt* match = sr->routing_table;
    while(match){
        uint32_t dist =  ip_hdr->ip_src & match->mask.s_addr;
        if(dist == match->dest.s_addr){
         // printf("AAAAA\n");
          curr_interface = sr_get_interface(sr, match->interface);
          break;
        }
      match = match->next;
    }
    memcpy(eth_hdr->ether_dhost, eth_hdr ->ether_shost, ETHER_ADDR_LEN);//destination host to be the mac address
    memcpy(eth_hdr->ether_shost, sr_get_interface(sr, match->interface)->addr, ETHER_ADDR_LEN);//source host to be the interface address
    uint32_t temp = ip_hdr ->ip_dst;
    ip_hdr -> ip_dst = ip_hdr -> ip_src;
    ip_hdr -> ip_src = temp;
    ip_hdr -> ip_ttl = INIT_TTL;
    icmp_hdr -> icmp_type = 0x00;
    icmp_hdr -> icmp_code = 0x00;
    icmp_hdr->icmp_sum = 0x0000;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr ->ip_len) - sizeof(sr_ip_hdr_t));
    
    
    //printf("echo reply:\n");
    //print_hdrs(packet,len);
    sr_send_packet(sr, packet, len, curr_interface->name);
}

void send_ICMP11(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){

  uint8_t* new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
                   + sizeof(sr_icmp_t11_hdr_t));
  
   sr_ethernet_hdr_t* a_eth_hdr = (sr_ethernet_hdr_t*)packet;
   sr_ip_hdr_t* a_ip_hdr = (sr_ip_hdr_t*)(packet+ sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* b_e_hdr = (sr_ethernet_hdr_t*)new_packet;
  sr_ip_hdr_t* b_ip_hdr = (sr_ip_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t* icmp_hdr = (sr_icmp_t11_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t)
                                                   + sizeof(sr_ip_hdr_t));
 
  b_e_hdr->ether_type = a_eth_hdr->ether_type;  
  memcpy(b_e_hdr->ether_dhost, a_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(b_e_hdr->ether_shost, a_eth_hdr ->ether_dhost, ETHER_ADDR_LEN);
  b_ip_hdr->ip_hl = a_ip_hdr->ip_hl;
  b_ip_hdr->ip_v = a_ip_hdr->ip_v;
  b_ip_hdr->ip_tos = a_ip_hdr->ip_tos;
  b_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  //printf("fewd2%d\n",htons(sizeof(sr_ip_hdr_t)));
  b_ip_hdr->ip_id = a_ip_hdr->ip_id;
  b_ip_hdr->ip_off = a_ip_hdr->ip_off;
  b_ip_hdr->ip_ttl = INIT_TTL;
  b_ip_hdr->ip_p = ip_protocol_icmp;
  b_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
  b_ip_hdr->ip_dst = a_ip_hdr->ip_src;
  b_ip_hdr->ip_sum = 0;
  b_ip_hdr->ip_sum = cksum(b_ip_hdr, sizeof(sr_ip_hdr_t));
  //checksum problem
  //uint8_t temp = 3;
  icmp_hdr->icmp_type = 11;
  icmp_hdr->icmp_code = 0;
  memcpy(icmp_hdr->data, a_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0x0000;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
  //icmp_hdr -> unused = 0;
 // printf("what I wanr\n");
  
  //print_hdrs(new_packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)+ sizeof(sr_icmp_t11_hdr_t));
  
    sr_send_packet(sr, new_packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
                   + sizeof(sr_icmp_t11_hdr_t), interface);

  

}
void send_ICMP3_TYPE1(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){

  uint8_t* new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
                   + sizeof(sr_icmp_t11_hdr_t));
  
   sr_ethernet_hdr_t* a_eth_hdr = (sr_ethernet_hdr_t*)packet;
   sr_ip_hdr_t* a_ip_hdr = (sr_ip_hdr_t*)(packet+ sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* b_e_hdr = (sr_ethernet_hdr_t*)new_packet;
  sr_ip_hdr_t* b_ip_hdr = (sr_ip_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t* icmp_hdr = (sr_icmp_t11_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t)
                                                   + sizeof(sr_ip_hdr_t));
 
  b_e_hdr->ether_type = a_eth_hdr->ether_type;  
  memcpy(b_e_hdr->ether_dhost, a_eth_hdr->ether_shost, ETHER_ADDR_LEN);
   struct sr_if* new_interface;

  struct sr_rt* match = sr->routing_table;
  while(match)
  {
    uint32_t dist = a_ip_hdr->ip_src & match->mask.s_addr;
    if(dist == match->dest.s_addr)
    {
      new_interface = sr_get_interface(sr, match->interface);
    }
    match = match->next;
   }
  memcpy(b_e_hdr->ether_shost, new_interface->addr, ETHER_ADDR_LEN);
  b_ip_hdr->ip_hl = a_ip_hdr->ip_hl;
  b_ip_hdr->ip_v = a_ip_hdr->ip_v;
  b_ip_hdr->ip_tos = a_ip_hdr->ip_tos;
  b_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  //printf("fewd2%d\n",htons(sizeof(sr_ip_hdr_t)));
  b_ip_hdr->ip_id = a_ip_hdr->ip_id;
  b_ip_hdr->ip_off = a_ip_hdr->ip_off;
  b_ip_hdr->ip_ttl = a_ip_hdr -> ip_ttl;
  b_ip_hdr->ip_p = ip_protocol_icmp;
  b_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
  b_ip_hdr->ip_dst = a_ip_hdr->ip_src;
  b_ip_hdr->ip_sum = 0;
  b_ip_hdr->ip_sum = cksum(b_ip_hdr, sizeof(sr_ip_hdr_t));
  //checksum problem
  //uint8_t temp = 3;
  icmp_hdr->icmp_type = 3;
  icmp_hdr->icmp_code = 1;
  memcpy(icmp_hdr->data, a_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0x0000;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
  //icmp_hdr -> unused = 0;
 // printf("what I wanr\n");
  
  //print_hdrs(new_packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)+ sizeof(sr_icmp_t11_hdr_t));
  
    sr_send_packet(sr, new_packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
                   + sizeof(sr_icmp_t11_hdr_t), new_interface->name);

  

}

void send_ICMP3_TYPE0(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){

  uint8_t* new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
                   + sizeof(sr_icmp_t11_hdr_t));
  
   sr_ethernet_hdr_t* a_eth_hdr = (sr_ethernet_hdr_t*)packet;
   sr_ip_hdr_t* a_ip_hdr = (sr_ip_hdr_t*)(packet+ sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* b_e_hdr = (sr_ethernet_hdr_t*)new_packet;
  sr_ip_hdr_t* b_ip_hdr = (sr_ip_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t* icmp_hdr = (sr_icmp_t11_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t)
                                                   + sizeof(sr_ip_hdr_t));
 
  b_e_hdr->ether_type = a_eth_hdr->ether_type;  
  memcpy(b_e_hdr->ether_dhost, a_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(b_e_hdr->ether_shost,a_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  b_ip_hdr->ip_hl = a_ip_hdr->ip_hl;
  b_ip_hdr->ip_v = a_ip_hdr->ip_v;
  b_ip_hdr->ip_tos = a_ip_hdr->ip_tos;
  b_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  //printf("fewd2%d\n",htons(sizeof(sr_ip_hdr_t)));
  b_ip_hdr->ip_id = a_ip_hdr->ip_id;
  b_ip_hdr->ip_off = a_ip_hdr->ip_off;
  b_ip_hdr->ip_ttl = a_ip_hdr -> ip_ttl;
  b_ip_hdr->ip_p = ip_protocol_icmp;
  b_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
  b_ip_hdr->ip_dst = a_ip_hdr->ip_src;
  b_ip_hdr->ip_sum = 0;
  b_ip_hdr->ip_sum = cksum(b_ip_hdr, sizeof(sr_ip_hdr_t));
  //checksum problem
  //uint8_t temp = 3;
  icmp_hdr->icmp_type = 3;
  icmp_hdr->icmp_code = 0;
  memcpy(icmp_hdr->data, a_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0x0000;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
  //icmp_hdr -> unused = 0;
 // printf("what I wanr\n");
  
  //print_hdrs(new_packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)+ sizeof(sr_icmp_t11_hdr_t));
    sr_send_packet(sr, new_packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
                   + sizeof(sr_icmp_t11_hdr_t), interface);
  

}

void send_ICMP3_TYPE3(struct sr_instance* sr, uint8_t* packet,unsigned int len, char* interface){

  uint8_t* new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
                   + sizeof(sr_icmp_t11_hdr_t));
  
   sr_ethernet_hdr_t* a_eth_hdr = (sr_ethernet_hdr_t*)packet;
   sr_ip_hdr_t* a_ip_hdr = (sr_ip_hdr_t*)(packet+ sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* b_e_hdr = (sr_ethernet_hdr_t*)new_packet;
  sr_ip_hdr_t* b_ip_hdr = (sr_ip_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t* icmp_hdr = (sr_icmp_t11_hdr_t*)(new_packet+ sizeof(sr_ethernet_hdr_t)
                                                   + sizeof(sr_ip_hdr_t));
 
  b_e_hdr->ether_type = a_eth_hdr->ether_type;  
  memcpy(b_e_hdr->ether_dhost, a_eth_hdr->ether_shost, ETHER_ADDR_LEN);
   struct sr_if* new_interface;

  struct sr_rt* match = sr->routing_table;
  while(match)
  {
    uint32_t dist = a_ip_hdr->ip_src & match->mask.s_addr;
    if(dist == match->dest.s_addr)
    {
      new_interface = sr_get_interface(sr, match->interface);
    }
    match = match->next;
   }
  memcpy(b_e_hdr->ether_shost, new_interface->addr, ETHER_ADDR_LEN);
  b_ip_hdr->ip_hl = a_ip_hdr->ip_hl;
  b_ip_hdr->ip_v = a_ip_hdr->ip_v;
  b_ip_hdr->ip_tos = a_ip_hdr->ip_tos;
  b_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  //printf("fewd2%d\n",htons(sizeof(sr_ip_hdr_t)));
  b_ip_hdr->ip_id = a_ip_hdr->ip_id;
  b_ip_hdr->ip_off = a_ip_hdr->ip_off;
  b_ip_hdr->ip_ttl = INIT_TTL;
  b_ip_hdr->ip_p = ip_protocol_icmp;
  b_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
  b_ip_hdr->ip_dst = a_ip_hdr->ip_src;
  b_ip_hdr->ip_sum = 0;
  b_ip_hdr->ip_sum = cksum(b_ip_hdr, sizeof(sr_ip_hdr_t));
  //checksum problem
  //uint8_t temp = 3;
  icmp_hdr->icmp_type = 3;
  icmp_hdr->icmp_code = 3;
  memcpy(icmp_hdr->data, a_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0x0000;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
  //icmp_hdr -> unused = 0;
 // printf("what I wanr\n");
  
  //print_hdrs(new_packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)+ sizeof(sr_icmp_t11_hdr_t));
  
    sr_send_packet(sr, new_packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
                   + sizeof(sr_icmp_t11_hdr_t), new_interface->name);

  

}