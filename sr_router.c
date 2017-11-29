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
#include <stdlib.h>
#include <string.h>

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
  uint16_t etherType = ethertype(packet);
  // get interface of the router
  struct sr_if * rec_router_interface = sr_get_interface(sr, interface);

  // get the header of ethernet and arp
  sr_ethernet_hdr_t * ethernetHdr = get_ethernet_hdr(packet);
  switch(etherType) 
  {
    case ethertype_arp:
      // check the length of the packet
      if(check_length_arp(len) != (uint8_t)1) 
      {
	// the length is less than the size of packet
	return;
      }
      // first is handling arp
      sr_arp_hdr_t * arpHdr = get_arp_hdr(packet);
      ethernetHdr = get_ethernet_hdr(packet);
      // check the arp op code to see whether reply or request
      if(ntohs(arpHdr->ar_op) == arp_op_request) 
      {
	printf("trying to send arprequest\n");
	sr_handle_arp_request(sr, arpHdr, rec_router_interface, ethernetHdr);
      }
      else if(ntohs(arpHdr->ar_op) == arp_op_reply) 
      {
	printf("trying to send arpreply\n");
	sr_handle_arp_reply(sr, arpHdr, rec_router_interface);
      }
      else 
      {
	// since no request or reply
	return;
      }
      break;
    case ethertype_ip:
      // second is handling ip
      // check the length of the packet
      if(check_length_ip(len) != (uint8_t)1) 
      {
	// the length is less than the size of packet
	return;
      }
      // get the header of ethernet and arp
      //sr_ethernet_hdr_t * ethernetHdr = get_ethernet_hdr(packet);
      sr_ip_hdr_t* ipHdr = get_ip_hdr(packet);
      // validate the IP header
      // checksum
      if(check_checksum_ip(ipHdr) != (uint8_t)1) 
      {
	return;
      }
      // check IPv4
      if(ipHdr->ip_v != (unsigned int)4) 
      {
	return;
      }
      // check ip_hl
      //if(ipHdr->ip_hl != (unsigned int)4) 
      //{
      //printf("%d\n", ipHdr->ip_hl);
      //	return;
      //}
      // check ip_len TODO
      if(ipHdr->ip_len < sizeof(sr_ip_hdr_t)) 
      {
	return;
      }
      // get interface of the router
      // struct sr_if * rec_router_interface = sr_get_interface(sr, interface);
      // struct sr_if * rec_router_interface = sr_get_interface(sr, interface);

      // check the ip address of the destination and the interface
      // first case if the ip packet is for the router, then do something
      printf("printing the ip for checking replying\n");
      if(sr_check_ip(sr, packet)) 
      //if(rec_router_interface->ip == ipHdr->ip_dst) 
      {
	// do the handling ip here TODO
	// check ip_p to see which protocal it is sending
	if(ipHdr->ip_p == ip_protocol_icmp) 
	{
	  printf("this is the place we are looking for and it is icmp\n");
	  // if it is an icmp packet
	  // generate ICMP echo reply
	  // get the icmp packet
	  sr_icmp_hdr_t * icmpHdr = get_icmp_hdr(packet);
	  // check the icmp (checksum and length)
	  if(check_length_icmp(len) != (uint8_t)1) 
	  {
	    printf("not sending pack because the length\n");
	    return;
	  }
	  if(check_checksum_icmp(icmpHdr) != (uint8_t)1) 
	  {
	    printf("not sending pack because the checksum\n");
	    return;
	  }
	  // assume all the icmp is request and echo
       	  //uint8_t icmp_type = 0x0008;
  	  //uint8_t icmp_code = 0x0;
	  if(icmpHdr->icmp_type == 8) 
	  {
	    printf("send icmp echo reply since this is the place that we are looking for\n");
	    // send icmp echo reply TODO
	    sr_send_icmp_reply(sr, packet, 
		len, rec_router_interface);
	  }
	  printf("not sending pack because the icmp_type\n");
	}
	else 
	{
	  printf("this is the place we are looking for and it is tcp/udp\n");
	  printf("unreacheable\n");
	  // not doing anything with anything else 
	  // TCP or UDP
	  // send icmp port unreadable TODO
	  sr_send_icmp_unreachable(sr, packet, rec_router_interface);
	}
      }

      printf("inside ip if ip are not the same\n");
      // second case if the ip packet is not for this network, do sth
      // check ip_ttl <= 1 ICMP time exceeded
      if(ipHdr->ip_ttl <= 1) 
      {
	// do something about icmp time exceeded
	printf("send icmp exceeded since the ttl <= 1 and it is still not the place \
	    that we are looking for\n");
	sr_send_icmp_exceeded(sr, packet, rec_router_interface);
	return;
      }
      // reduce ttl and update checksum
      // ipHdr->ip_ttl--;
      // do something about the next hop address and forward the packet
      // to next hop (TODO)  	
      // since we are sending back with the reply, so send back to the
      // source interface
      //struct sr_if* send_router_interface = sr_ip_to_inferface(sr, 
      //  ipHdr->ip_src);
      struct sr_if* send_router_interface = sr_ip_to_inferface(sr, 
	  ipHdr->ip_dst);
      // find the lpm entry (matching interface)
      if(send_router_interface) 
      {
	// reduce ttl and update checksum
	ipHdr->ip_ttl--;
	ipHdr->ip_sum = 0;					/* checksum */
	ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
	// updae the frame headr's source and destination fields
	struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache), 
	    ipHdr->ip_dst);
	// check the entry
	if(entry) 
	{
	  printf("find the lpm, and find the entry, and send it\n");
	  // if the entyr is not null
	  // modify the ethernet source and destination values
	  memcpy(ethernetHdr->ether_shost, send_router_interface->addr, ETHER_ADDR_LEN);
	  memcpy(ethernetHdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
	  sr_send_packet(sr, packet, len, send_router_interface->name);
	  free(entry);
	  return;
	}
	else 
	{
	  printf("find the lpm, but do not find the entry, so send arp request\n");
	  // if the entry is null
	  // add ARP request queue
	  struct sr_arpreq * reqQueue = sr_arpcache_queuereq(&(sr->cache),
	      ipHdr->ip_dst, packet, len, send_router_interface->name);
	  handle_arpreq(sr, reqQueue);
	  return;
	}
      }
      else 
      {
	printf("not find the lpm, therefore not reachable\n");
	sr_send_icmp_unreachable(sr, packet, rec_router_interface);
      }
      break;
    default:
      // nothing received
      return;
  }

}/* end sr_ForwardPacket */

void sr_handle_arp_reply(struct sr_instance * sr, sr_arp_hdr_t* arpHdr,
    struct sr_if * rec_router_interface) 
{
  // check the ip address
  if(arpHdr->ar_tip != rec_router_interface->ip) 
  {
    return;
  }
  pthread_mutex_lock(&(sr->cache.lock));
  // cache reply
  struct sr_arpreq * request = sr_arpcache_insert(&(sr->cache),
      arpHdr->ar_sha, arpHdr->ar_sip);
  // not null means it is in the list
  // if it is in the list then send the packets waiting on this reply
  if(request) 
  {
    // get the current packet and try to forward it to the desintaion
    // since the current packet is not desination, it is not NULL
    // this is the entry queue
    struct sr_packet * dest = request->packets;
    sr_send_arp_reply(dest, sr, arpHdr, rec_router_interface); 
    // drop the request from the queue since it is sent
    sr_arpreq_destroy(&(sr->cache), request);
  }
  pthread_mutex_unlock(&(sr->cache.lock));
}

void sr_send_arp_reply(struct sr_packet * dest,  struct sr_instance * sr, sr_arp_hdr_t* arpHdr,
    struct sr_if * rec_router_interface) 
{
  pthread_mutex_lock(&(sr->cache.lock));
    // loop until find the desination (which should be null since does
    // not have next packet if reach the end)
    printf("function call arp reply\n");
    while(dest) 
    {
      // do the forwarding here
      uint8_t * packet = dest->buf;
      // get the header of ethernet and ip
      sr_ethernet_hdr_t * ethernetHdr = get_ethernet_hdr(packet);
      sr_ip_hdr_t * ipHdr = get_ip_hdr(packet);
      // compute checksum
      ipHdr->ip_sum = 0;
      ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
      // make the dest mac to be the destination source 
      // (usually not change)
      memcpy(ethernetHdr->ether_dhost, arpHdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(ethernetHdr->ether_shost, rec_router_interface->addr, 
	  ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, dest->len, rec_router_interface->name);
      // go to the next dest to see whether it is the end
      dest = dest->next;
    }
  pthread_mutex_unlock(&(sr->cache.lock));
}

void sr_handle_arp_request(struct sr_instance * sr, sr_arp_hdr_t * arpHdr,
    struct sr_if * rec_router_interface, sr_ethernet_hdr_t * ethernetHdrR) 
{
  // insert the request to the request queue
  sr_arpcache_insert(&(sr->cache), arpHdr->ar_sha, arpHdr->ar_sip);
  // responds with reply
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t * packet = (uint8_t *) calloc(1, len);
  // get the header of ethernet and arp
  sr_ethernet_hdr_t * ethernetHdr = get_ethernet_hdr(packet);
  sr_arp_hdr_t * arpHdrR = get_arp_hdr(packet);
  // set the arp hdr
  arpHdrR->ar_hrd = arpHdr->ar_hrd; 
  arpHdrR->ar_pro = arpHdr->ar_pro;            
  arpHdrR->ar_hln = arpHdr->ar_hln;           
  arpHdrR->ar_pln = arpHdr->ar_pln;  
  // TODO: check here           
  arpHdrR->ar_op = htons(arp_op_reply);   
  // set the source ip to the current interface ip       
  arpHdrR->ar_sip = rec_router_interface->ip;  
  // set the destination ip to the previous source ip
  arpHdrR->ar_tip = arpHdr->ar_sip;
  // set the MAC address follow the same idea
  memcpy(arpHdrR->ar_sha, rec_router_interface->addr, ETHER_ADDR_LEN); 
  memcpy(arpHdrR->ar_tha, arpHdr->ar_sha, ETHER_ADDR_LEN);                   

  // set the ethernet hdr
  ethernetHdr->ether_type = ntohs(ethertype_arp);
  memcpy(ethernetHdr->ether_dhost, 
      ethernetHdrR->ether_shost, ETHER_ADDR_LEN); 
  memcpy(ethernetHdr->ether_shost, 
      rec_router_interface->addr, ETHER_ADDR_LEN); 
  sr_send_packet(sr, packet, len, rec_router_interface->name);
}

void send_arp_request(struct sr_instance * sr, struct sr_arpreq * req) 
{
  // responds with reply
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t * packet = (uint8_t *) calloc(1, len);
  // get the header of ethernet and arp
  sr_ethernet_hdr_t * ethernetHdr = get_ethernet_hdr(packet);
  sr_arp_hdr_t * arpHdr = get_arp_hdr(packet);
  // since we are sending back with the reply, so send back to the
  // source interface
  struct sr_if* send_router_interface = sr_ip_to_inferface(sr, 
      req->ip);

  // set the arp hdr
  arpHdr->ar_hrd = htons(arp_hrd_ethernet); 
  arpHdr->ar_pro = htons(ethertype_ip);            
  arpHdr->ar_hln = ETHER_ADDR_LEN;           
  arpHdr->ar_pln = 4;  
  // TODO: check here           
  arpHdr->ar_op = htons(arp_op_request);   
  // set the source ip to the current interface ip       
  arpHdr->ar_sip = send_router_interface->ip;  
  // set the destination ip to the previous source ip
  arpHdr->ar_tip = req->ip;
  // set the MAC address follow the same idea
  memcpy(arpHdr->ar_sha, send_router_interface->addr, ETHER_ADDR_LEN); 
  //memset(def, 0xFF, ETHER_ADDR_LEN);
  memset(arpHdr->ar_tha, 0xFF, ETHER_ADDR_LEN);                   

  // set the ethernet hdr
  ethernetHdr->ether_type = htons(ethertype_arp);
  memset(ethernetHdr->ether_dhost, 
      0xFF, ETHER_ADDR_LEN); 
  memcpy(ethernetHdr->ether_shost, 
      send_router_interface->addr, ETHER_ADDR_LEN); 
  sr_send_packet(sr, packet, len, send_router_interface->name);
}

void sr_send_icmp_unreachable(struct sr_instance *sr, uint8_t * whole_packet, 
    struct sr_if * rec_router_interface) 
{
  // unreachable type and code
  uint8_t icmp_type = 0x0003;
  uint8_t icmp_code = 0x0003;
  // responds with icmp unreachable 
  // allocate space for new icmp packet
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
    + sizeof(sr_icmp_hdr_t);
  uint8_t * packet = (uint8_t *) calloc(1, len);

  // get the header of ethernet and ip and icmp
  sr_ethernet_hdr_t * ethernetHdrR = get_ethernet_hdr(whole_packet);
  sr_ip_hdr_t * ipHdrR = get_ip_hdr(whole_packet);

  sr_ethernet_hdr_t * ethernetHdr = get_ethernet_hdr(packet);
  sr_ip_hdr_t * ipHdr = get_ip_hdr(packet);
  sr_icmp_hdr_t * icmpHdr = get_icmp_hdr(packet);

  icmpHdr->icmp_type = icmp_type;
  icmpHdr->icmp_code = icmp_code;
  icmpHdr->icmp_sum = 0;
  icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_hdr_t));
  memcpy(icmpHdr->data, ipHdrR, ICMP_DATA_SIZE);

  ipHdr->ip_hl = ipHdrR->ip_hl;		/* header length */
  ipHdr->ip_v = ipHdrR->ip_v;			/* version */
  ipHdr->ip_tos = ipHdrR->ip_tos;		/* type of service */
  ipHdr->ip_len = sizeof(sr_ip_hdr_t)
    + sizeof(sr_icmp_hdr_t);		/* total length */
  ipHdr->ip_id = 0;					/* identification */
  ipHdr->ip_off = IP_DF;				/* fragment offset field */
  ipHdr->ip_ttl = INIT_TTL;			/* time to live */
  ipHdr->ip_p = ip_protocol_icmp;		/* protocol */
  ipHdr->ip_sum = 0;					/* checksum */
  ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
  ipHdr->ip_src = rec_router_interface->ip;
  ipHdr->ip_dst = ipHdrR->ip_src;	/* source and dest address */

  // set the ethernet hdr
  ethernetHdr->ether_type = htons(ethertype_ip);
  memcpy(ethernetHdr->ether_dhost, 
      ethernetHdrR->ether_shost, ETHER_ADDR_LEN); 
  memcpy(ethernetHdr->ether_shost, 
      rec_router_interface->addr, ETHER_ADDR_LEN); 

  // since we are sending back with the reply, so send back to the
  // source interface
  struct sr_if* send_router_interface = sr_ip_to_inferface(sr, 
      ipHdrR->ip_src);
  // set the ethernet hdr
  sr_send_packet(sr, packet, len, send_router_interface->name);
}

void sr_send_icmp_exceeded(struct sr_instance *sr, uint8_t * whole_packet, 
    struct sr_if * rec_router_interface) 
{
  // unreachable type and code
  uint8_t icmp_type = 0x000b;
  uint8_t icmp_code = 0x0;
  // responds with icmp unreachable 
  // allocate space for new icmp packet
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
    + sizeof(sr_icmp_hdr_t);
  uint8_t * packet = (uint8_t *) calloc(1, len);

  // get the header of ethernet and ip and icmp
  sr_ethernet_hdr_t * ethernetHdrR = get_ethernet_hdr(whole_packet);
  sr_ip_hdr_t * ipHdrR = get_ip_hdr(whole_packet);

  sr_ethernet_hdr_t * ethernetHdr = get_ethernet_hdr(packet);
  sr_ip_hdr_t * ipHdr = get_ip_hdr(packet);
  sr_icmp_hdr_t * icmpHdr = get_icmp_hdr(packet);

  icmpHdr->icmp_type = icmp_type;
  icmpHdr->icmp_code = icmp_code;
  icmpHdr->icmp_sum = 0;
  icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_hdr_t));
  memcpy(icmpHdr->data, ipHdrR, ICMP_DATA_SIZE);

  ipHdr->ip_hl = ipHdrR->ip_hl;		/* header length */
  ipHdr->ip_v = ipHdrR->ip_v;			/* version */
  ipHdr->ip_tos = ipHdrR->ip_tos;		/* type of service */
  ipHdr->ip_len = htons(sizeof(sr_ip_hdr_t)
      + sizeof(sr_icmp_hdr_t));		/* total length */
  ipHdr->ip_id = 0;					/* identification */
  ipHdr->ip_off = htons(IP_DF);				/* fragment offset field */
  ipHdr->ip_ttl = INIT_TTL;			/* time to live */
  ipHdr->ip_p = ip_protocol_icmp;		/* protocol */
  ipHdr->ip_sum = 0;					/* checksum */
  ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
  ipHdr->ip_src = rec_router_interface->ip;
  ipHdr->ip_dst = ipHdrR->ip_src;	/* source and dest address */

  // set the ethernet hdr
  ethernetHdr->ether_type = htons(ethertype_ip);
  memcpy(ethernetHdr->ether_dhost, 
      ethernetHdrR->ether_shost, ETHER_ADDR_LEN); 
  memcpy(ethernetHdr->ether_shost, 
      rec_router_interface->addr, ETHER_ADDR_LEN); 

  // since we are sending back with the reply, so send back to the
  // source interface
  struct sr_if* send_router_interface = sr_ip_to_inferface(sr, 
      ipHdrR->ip_src);
  // set the ethernet hdr
  sr_send_packet(sr, packet, len, send_router_interface->name);
}

void sr_send_icmp_reply(struct sr_instance *sr, uint8_t * packet, 
    unsigned int len, struct sr_if * rec_router_interface) 
{
  // unreachable type and code
  uint8_t icmp_type = 0x0;
  uint8_t icmp_code = 0x0;
  // responds with icmp reply 
  // get the header of ethernet and ip and icmp
  sr_ethernet_hdr_t * ethernetHdr = get_ethernet_hdr(packet);
  sr_ip_hdr_t * ipHdr = get_ip_hdr(packet);
  sr_icmp_hdr_t * icmpHdr = get_icmp_hdr(packet);

  icmpHdr->icmp_type = icmp_type;
  icmpHdr->icmp_code = icmp_code;
  icmpHdr->icmp_sum = 0;
  icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_hdr_t));

  ipHdr->ip_sum = 0;					/* checksum */
  ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
  uint32_t prev_sip = ipHdr->ip_src;
  ipHdr->ip_src = ipHdr->ip_dst;
  ipHdr->ip_dst = prev_sip;	/* source and dest address */

  // since we are sending back with the reply, so send back to the
  // source interface
  struct sr_if* send_router_interface = sr_ip_to_inferface(sr, 
      ipHdr->ip_src);

  // set the ethernet hdr
  memcpy(ethernetHdr->ether_dhost, 
      ethernetHdr->ether_shost, ETHER_ADDR_LEN); 
  memcpy(ethernetHdr->ether_shost, 
      send_router_interface->addr, ETHER_ADDR_LEN); 

  // set the ethernet hdr
  sr_send_packet(sr, packet, len, send_router_interface->name);
}

struct sr_if* sr_ip_to_inferface(struct sr_instance* sr, uint32_t dstAddr)
{
  struct sr_rt* rt_walker = 0;
  rt_walker = sr->routing_table;
  struct sr_rt* rt_lpm_walker = 0;
  while(rt_walker)
  {
    if((!rt_lpm_walker) || (rt_lpm_walker->mask.s_addr < rt_walker->mask.s_addr)) {
      uint32_t dst =  dstAddr & rt_walker->mask.s_addr;
      uint32_t dstNetwork = rt_walker->dest.s_addr & rt_walker->mask.s_addr;
      if(dst == dstNetwork)
      {
	//if_walker = sr_get_interface(sr, rt_walker->interface); 
	//return if_walker;
	rt_lpm_walker = rt_walker; 
      }
    }
    rt_walker = rt_walker->next;
  }
  struct sr_if* if_walker = sr_get_interface(sr, rt_lpm_walker->interface);
  return if_walker;
} 

uint8_t sr_check_ip(struct sr_instance * sr, uint8_t* packet) 
{
  struct sr_ip_hdr * ipHdr = get_ip_hdr(packet);
  struct sr_if * interfaces = sr->if_list;
  uint8_t result = 0;
  while(interfaces) 
  {
    if(interfaces->ip == ipHdr->ip_dst) 
    {
      result = 1;
      printf("findinggggggggggggggggggggggggggggggggggggg\n");
      return result;
    }
    interfaces = interfaces->next;
  }
  printf("nooooooooooooooooooooooo\n");
  return result;
}
