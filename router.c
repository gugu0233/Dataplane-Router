#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>
#define HwMADDR 6 // mac addr len

// route finder
int get_arp_index(struct route_table_entry *best_route, int arptable_len, struct arp_table_entry *arptable)
{
	int i;
	int indx = -1;
	for (i = 0; i < arptable_len; i++)
		if (arptable[i].ip == best_route->next_hop)
		{
			indx = i;
			break;
		}
	return indx;
}

// function for rtable sorting (qsort)
int qsort_f(const void *a, const void *b)
{
	struct route_table_entry *r_a = (struct route_table_entry *)a;
	struct route_table_entry *r_b = (struct route_table_entry *)b;

	uint32_t prfx_a = r_a->prefix;
	uint32_t prfx_b = r_b->prefix;

	uint32_t mask_a = r_a->mask;
	uint32_t mask_b = r_b->mask;

	if (prfx_a == prfx_b)
		return mask_a - mask_b;
	else
		return (prfx_a - prfx_b);
}

// binary search alg
int binary_search(struct route_table_entry *rtable, int left, int right, uint32_t dest)
{
	while (left <= right)
	{
		int mid = (left + right) / 2;
		if (rtable[mid].prefix == (rtable[mid].mask & dest))
			return mid;
		else if (rtable[mid].prefix > (rtable[mid].mask & dest))
			right = mid - 1;
		else
			left = mid + 1;
	}
	return -1;
}

// get best route with LPM alg
struct route_table_entry *get_best_route(struct route_table_entry *rtable, int rtable_len, uint32_t d_addr)
{
	struct route_table_entry *best_route = NULL;
	int indx = binary_search(rtable, 0, rtable_len, d_addr);
	int i;
	for (i = indx; i < rtable_len; i++)
		if ((d_addr & rtable[i].mask) == rtable[i].prefix && (best_route == NULL || (best_route->mask < rtable[i].mask)))
			best_route = &rtable[i];
	return best_route;
}

// get packet from queue & send it
void send_pkt_inQ(queue q, struct route_table_entry *rtable, int rtable_len, int arptable_len, struct arp_table_entry *arptable)
{
	char *pkt = (char *)queue_deq(q);
	char payload[MAX_PACKET_LEN];
	size_t len;

	memcpy(&len, pkt, sizeof(size_t));
	memcpy(payload, pkt + sizeof(size_t), len);

	struct ether_header *pkt_eth_hdr = (struct ether_header *)payload;
	struct iphdr *pkt_ip_hdr = (struct iphdr *)(payload + sizeof(struct ether_header));
	struct route_table_entry *best_route = get_best_route(rtable, rtable_len, pkt_ip_hdr->daddr);

	int arp_index = get_arp_index(best_route, arptable_len, arptable);
	memcpy(pkt_eth_hdr->ether_dhost, arptable[arp_index].mac, HwMADDR);
	send_to_link(best_route->interface, payload, len);
}

void send_icmp(char *buf, int interface, int type, struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct icmphdr *icmp_hdr, size_t len)
{
	char pkt[MAX_PACKET_LEN];

	// eth hdr
	uint8_t aux_mac[HwMADDR];
	memcpy(aux_mac, eth_hdr->ether_dhost, HwMADDR);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, HwMADDR);
	memcpy(eth_hdr->ether_shost, aux_mac, HwMADDR);
	eth_hdr->ether_type = htons(0x0800);

	// ip hdr
	ip_hdr->tot_len = len;
	ip_hdr->ttl = 64;
	ip_hdr->protocol = 1;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
	uint32_t aux = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = aux;

	// icmp hdr
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = htons(checksum((u_int16_t *)icmp_hdr, sizeof(struct icmphdr)));

	// create the packet & send it
	memcpy(pkt, eth_hdr, sizeof(struct ether_header));
	memcpy(pkt + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(pkt + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
	send_to_link(interface, pkt, len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// routing table
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory allocation fail");
	int rtable_len = read_rtable(argv[1], rtable);
	// sort routing table
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), qsort_f);

	// arp table
	struct arp_table_entry *arptable = malloc(sizeof(struct arp_table_entry) * 100000);
	DIE(arptable == NULL, "memory allocation fail");
	int arptable_len;

	uint8_t mac[HwMADDR];
	uint8_t mac_broadcast[HwMADDR];
	int i;
	for (i = 0; i < HwMADDR; i++)
		mac_broadcast[i] = 0xff;

	// packet queue
	queue q = queue_create();

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1)
	{

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		get_interface_mac(interface, mac);

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
		struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

		len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

		// check packet type
		if (eth_hdr->ether_type == htons(0x0800)) // ip type
		{
			// if icmp req -> reply
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)) && ip_hdr->protocol == 1 && icmp_hdr->type == 8)
			{
				send_icmp(buf, interface, 0, eth_hdr, ip_hdr, icmp_hdr, len);
				continue;
			}

			// if packet corrupted -> drop it
			uint16_t checksum1 = ip_hdr->check;
			ip_hdr->check = 0;
			uint16_t checksum2 = checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr));
			if (ntohs(checksum1) != checksum2)
			{
				printf("checksum fail\n");
				continue;
			}

			// if ttl expired -> send icmp reply & drop it
			if (ip_hdr->ttl < 2)
			{
				send_icmp(buf, interface, 11, eth_hdr, ip_hdr, icmp_hdr, len);
				printf("ttl fail\n");
				continue;
			}
			else // ttl not expired -> decrement it & update checksum
			{
				ip_hdr->ttl--;
				ip_hdr->check = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr)));
			}

			// if route to send packet not found -> send icmp reply & drop it
			struct route_table_entry *best_route = get_best_route(rtable, rtable_len, ip_hdr->daddr);
			if (best_route == NULL)
			{
				send_icmp(buf, interface, 3, eth_hdr, ip_hdr, icmp_hdr, len);
				printf("dest unreachable\n");
				continue;
			}

			uint8_t rmac[HwMADDR];
			get_interface_mac(best_route->interface, rmac);

			int arp_index = get_arp_index(best_route, arptable_len, arptable);

			// if entry in arp table not found -> send arp req
			if (arp_index == -1)
			{
				char *packet = malloc(MAX_PACKET_LEN + sizeof(size_t));
				memcpy(packet + sizeof(size_t), buf, len);
				memcpy(packet, &len, sizeof(size_t));

				queue_enq(q, packet);

				struct ether_header *new_arp_eth_hdr = malloc(sizeof(struct ether_header));
				int i;
				for (i = 0; i < HwMADDR; i++)
					new_arp_eth_hdr->ether_dhost[i] = 0xff;
				memcpy(new_arp_eth_hdr->ether_shost, rmac, HwMADDR);
				new_arp_eth_hdr->ether_type = htons(0x0806);

				struct arp_header *new_arp_hdr = malloc(sizeof(struct arp_header));
				new_arp_hdr->htype = htons(1);
				new_arp_hdr->ptype = htons(0x0800);
				new_arp_hdr->hlen = HwMADDR;
				new_arp_hdr->plen = 4;
				new_arp_hdr->op = htons(1);
				for (i = 0; i < HwMADDR; i++)
					new_arp_hdr->tha[i] = 0x00;
				new_arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
				new_arp_hdr->tpa = best_route->next_hop;
				memcpy(new_arp_hdr->sha, rmac, HwMADDR);
				memcpy(new_arp_hdr->tha, mac_broadcast, HwMADDR);

				char arp_req[MAX_PACKET_LEN];
				memcpy(arp_req, new_arp_eth_hdr, sizeof(struct ether_header));
				memcpy(arp_req + sizeof(struct ether_header), new_arp_hdr, sizeof(struct arp_header));
				send_to_link(best_route->interface, arp_req, sizeof(struct ether_header) + sizeof(struct arp_header));
			}
			// if entry found -> send the packet
			else
			{
				memcpy(eth_hdr->ether_shost, rmac, HwMADDR);
				memcpy(eth_hdr->ether_dhost, arptable[arp_index].mac, HwMADDR);
				send_to_link(best_route->interface, buf, len);
			}
		}
		// arp type
		else if (eth_hdr->ether_type == htons(0x0806))
		{
			// if packet is arp req -> reply
			if (arp_hdr->op == htons(1) && arp_hdr->tpa == inet_addr(get_interface_ip(interface)))
			{

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, HwMADDR);
				memcpy(eth_hdr->ether_shost, mac, HwMADDR);

				memcpy(arp_hdr->tha, arp_hdr->sha, HwMADDR);
				memcpy(arp_hdr->sha, mac, HwMADDR);
				u_int32_t aux = arp_hdr->tpa;
				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = aux;
				arp_hdr->op = htons(2);

				send_to_link(interface, buf, len);
			}
			// if packet is arp reply -> new entry
			else if (arp_hdr->op == htons(2) && arp_hdr->tpa == inet_addr(get_interface_ip(interface)))
			{

				struct arp_table_entry *arp_entry = malloc(sizeof(struct arp_table_entry));
				memcpy(arp_entry->mac, arp_hdr->sha, HwMADDR);
				arp_entry->ip = arp_hdr->spa;

				arptable[arptable_len] = *arp_entry;
				arptable_len++;

				while (queue_empty(q) == 0)
					send_pkt_inQ(q, rtable, rtable_len, arptable_len, arptable);
			}
		}
	}
}