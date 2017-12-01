NAME: Renxu Hu
PID: A92067683
EMAIL: reh011@ucsd.edu

Unfortunately, I am not competing for the George Varghese Espresso Prize.

DESCRIPTION/OVERVIEW

	This program is a simple router implementation. The user can use this
implementation to ping the router inferfaces and app servers from the client,
to traceroute from the client to any of the router's interfaces and any of the
app servers, and at the same time, the user can download a file using HTTP from
one of the app servers with the wget command. With the help of vmware, I can 
create a vitural network, and with the help of wireshark, I can see the 
configuration of the packets that are transferred within the networks. The 
simple router implementation that I implemented is divided into two parts, IP
and ARP. IP is using routing table as the base to forward the packet; ARP is 
used to check the MAC address of the specific host.

DESIGN DECISION AND TRADEOFFS

	I realize that the design that I used to have is taking more time to 
send the arp packet because of the order of the insertion. Therefore, in
order to solve that, I implement the stack with the recursion to send the 
arp packet at the end; therefore, it will be faster to send the arp packet.

	When recived the raw ethernet frame, it will concern the packet with 
two consideration, and it will check whether it is an IP packet or an ARP 
packet. If it is a IP packet, we will check whether it is for me or other 
router. If it is for me and if it is a ICMP echo request, the router will 
send echo reply. Or if it is TCP/UDP, send ICMP port unreachable, and I will
explain the ICMP implementation below. 
	If the IP pakcet is not for the current interface, I will check the 
routing table, and perform the largest prefix matach to find the largest 
prefix interface. If there is a match, I will send ICMP net unreachable. If
there is a match, I will check the ARP cache. If there is a miss, I will 
send ARP request, and if the resent is larger than 5 times, then I will send
ICMP host unreachable. If there is a hit, I will send this frame to next hop.
	If it is a ARP packet, I will check whether it is a request or reply.
If it is a request to the current interface, I will construct an ARP reply 
and send it back. If it is a reply to the current interface, I will cache it,
and go through my request queue and send outstanding packets. The request 
queue will be constructed during IP forwarding.

	ARP Packet: 

	If it is a arp apcket, I will do the sanitation check (length of 
packet, and checksum, etc). I will then check the opcode to see what kind
of ARP packet is being sent. If it is an ARP request, update all fields of
the packet and use sr_send_packet() to send an ARP reply. If it is a reply,
I will updae the ARP cache and ARP queue. Send all the packets in the queue
to the destination.

	IP Packet:

	If it is an ip packet, I will do the sanitation check first(ip header
and checksum). Then I will check whether it is desintated for the current 
interface, if it is for the current interface, I will check the ip protocol,
and if it is a TCP/UDP, I will send ICMP port unreachable. If the is an echo
request, then genereate ICMP echo reply. If IP packet is not desinted to the 
router, then I will check the ip_ttl, if ttl <= 1 then send ICMP time exceeded.
Look up next-hop address by doing a longest prefix match on the routing table
using the packet's destination address. If it does not exist, send ICMP host
unreachable. If it doe exist, then reduce ttl and update checksum. From next-
hop address, determine outgoing interface and next-hop MAC addres. If 
necessary, send ARP request to determine MAC address. At last, forward packet 
to outgoing interface.

	IP Forwarding how to check the address of next hop:

	Longest prefix match, if packet not destined to router and ttl != 1,
check the routing table to see if a matching entry for the destination IP 
address exists. I can check the address with mask from the routing table. 
I will do a bitwise and between dest and mask to see if there is a matach. 
If mutiple matches, check to see which match has the longest mask.s_addr.

	Creating ARP Requests:

	If LPM entry (type sr_rt) is found, then reduce TTL and update
checksum for the IP header. Now, I will update the frame headers source 
and destination fields. Then I will do a sr_arpcache_lookup. gw.s_addr 
(next hop IP address) is one of the variables to be passed to the function. 
If it returns NULL, I will use sr_arpcache_queuereq function to add the ARP 
request to the ARP request queue. Then I will send the sr instance and the 
queue to handle_arpreq. 
	
	Handle_arpreq function in arpcache.c:

	If the lookup returned an arp entry, then modify the Ethernet
source and destination values and use sr_send_packet to handle the arp 
request. 

	ICMP TYPE 11 handle:

	Check if the destination IP address of the packet is not equal to the
IP addresses of the router interfaces. If not destined and TTL of the IP header 
packet == 1, create an ICMP type 11 (time exceeded) packet. Then, send the 
packet using sr_send_packet. The data field in the ICMP segment is 28 bytes 
starting from the IP header of the original packet which the router received.

	ICMP handle:

	Bascially, the ICMP packet will return different errors that the IP 
packet is encountered. There are mutiple errors that IP packet will 
encounter, host unreachable, port unreachable, live time exceeded, and network
unreachable. I will send the ICMP packet with different error code and type. 
