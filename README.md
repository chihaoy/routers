# pa2a-starter

## Info

Name: Chihao Yu

PID: A16248350

Email: chy007@ucsd.edu

## Description and Overview
Describe in brief what files you changed and what they should do.  
example graph
host1--------router1-----host3
              |
              |
              |
              |
            host2
If the packer wants to send from host1 to host3, the whole process goes like this, first the host1 send the arp request to router 1 and try to get the mac address of router1, and the router 1 will send the packet contains the mac address of router1 and then the host1 can send the packet to router 1. And then once it reaches the router 1, it will put it into the queue, for every entry in the queue, each entry is represented by destination address of the packet(in this case it is host3) and that packet will be put under this entry. And then the router 1 will send the arp request to host 3 and try to get the mac address of host 3. And the host 3 will send the mac address of host 3 to router 1. And then we go to the entry of the queue corresponds to the ip address of host 3 and send all the packets(put mac address in) under that entry.

handle packets:differentiate between ip packets and arp packets. And for the arp packets(differentiate between handle arp request and handle arp reply)
handle ip packet, I first check if the packet is destined for the router itself(simply check all the router's interface and see if there is a match), if it is, we send the echo reply. Otherwise, we check the routing table, if the dst id is in the routing table, we put it into the queue and wait to be sent(just like what I described above. Otherwise, we send ICMP type 3 code 0 back to the source saying the DESTINATION NET UNREACHABLE. 

handle_arp_request:this is basically between host and routers when the hosts want to know the mac address of the router and the arp request is from the host 1 to the router 1 and then it basically send the arp reply back to the host so host can send it to the router1.We simply use the mac address from the request packet for the source address of the reply packet sent back

handle_arp_reply:this will be called when the it gets the mac address of the destination host and then it will check into the queue and send the packet corrsponding to the destination IP address

send_echo_reply: This is for when the ip address is one of the router's interface

ICMP 3 type 0:When the IP address not in the routing table
ICMP 3 TYPE 1:When the arp request is sent 5 times and still did not get arp reply
ICMP 11:When the ttl reaches zerp

handle_arpreq:When the arp request sent less than 5 times, boradcast the packet otherwise, we delete the packect in the queue
