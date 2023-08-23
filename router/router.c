#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

queue cache_queue;
queue packets;

int get_ones_from_mask(int mask) {
	int nr = 0;
	for (int i = 0; i < 31; i++) {
		if (((mask >> i) & 1) != 0) nr++;
	}
	
	return nr;
}

void insert(struct TrieNode* root, struct route_table_entry* ip)
{
	int mask_len = get_ones_from_mask(ip->mask);
	struct TrieNode* node = root;
	// parcurg in functie de cate cifre de 1 are masca
	for (int i = 0; i < mask_len; i++) {
		// ma duc stanga sau dreapta in functie de prefix
		if (((ip->prefix >> i) & 1) == 0) {
			if (node->st0 == NULL) node->st0 = calloc(1, sizeof(struct TrieNode));
			node = node->st0;
		} else {
			if (node->dr1 == NULL) node->dr1 = calloc(1, sizeof(struct TrieNode));
			node = node->dr1;
		}
	}
	node->route = ip;  // cand am terminat masca, pun structura in trie
}

struct route_table_entry* get_best_route(struct TrieNode* root, int ip) {
	struct route_table_entry* best_route = NULL;
	struct TrieNode* node = root;
	int i = 0;
	// parcurg trie in functie de ip si intorc ultimul element nenul gasit
	while (node != NULL) {
		if (node->route != NULL) best_route = node->route;
		if (((ip >> i) & 1) == 0) node = node->st0;
		else node = node->dr1;

		i++;
	}

	return best_route;
}

void insert_rtable(struct TrieNode* root, struct route_table_entry* rtable, int len) {
	for (int i = 0; i < len; i++) insert(root, (rtable + i));
}

struct arp_entry* get_mac_from_cache(struct route_table_entry* best_route) {
	struct arp_entry *mac_from_cache = NULL;
	int cache_len = cache_queue->length;
	while (cache_len) {
		struct arp_entry* first = (struct arp_entry*) queue_deq(cache_queue);
		if(first->ip == best_route->next_hop) {
			mac_from_cache = first;
		}
		queue_enq(cache_queue, first);
		cache_len--;
	}

	return mac_from_cache;
}

void send_icmp(struct ether_header* eth_hdr, struct iphdr* iphdr, uint8_t type, int ip_router, int interface) {
	void* buffer = calloc(1, sizeof(struct icmphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
	struct ether_header *eth_hdr_aux = (struct ether_header *) buffer;
	struct iphdr *iphdr_aux = (struct iphdr *) (buffer + sizeof(struct ether_header));
	struct icmphdr* icmp = (struct icmphdr *) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr));

	// icmp
	icmp->type = type;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->checksum = htons(checksum((void*) icmp, sizeof(struct icmphdr)));

	// ipv4
	iphdr_aux->version = 4;
	iphdr_aux->ihl = 5;
	iphdr_aux->tos = 0;
	iphdr_aux->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	iphdr_aux->id = htons(1);
	iphdr_aux->frag_off = 0;
	iphdr_aux->ttl = 64;
	iphdr_aux->protocol = 1;
	iphdr_aux->daddr = iphdr->saddr;
	iphdr_aux->saddr = ip_router;
	iphdr_aux->check = 0;
	iphdr_aux->check = htons(checksum((void*) iphdr_aux, sizeof(struct iphdr)));

	// ether_header
	memcpy(eth_hdr_aux->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr_aux->ether_shost, eth_hdr->ether_dhost, 6);
	eth_hdr_aux->ether_type = eth_hdr->ether_type;

	send_to_link(interface, buffer, sizeof(struct icmphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// citesc tabela de rutare
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	int table_len = read_rtable(argv[1], rtable);
	struct TrieNode* root = calloc(1, sizeof(struct TrieNode));
	insert_rtable(root, rtable, table_len);

	// initializez coziile
	cache_queue = queue_create();
	packets = queue_create();

	while (1) {
		int interface;
		size_t len;

		// primesc ceva de la o interfata
		printf("inainte\n");
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		printf("dupa\n");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *iphdr;
		struct arp_header *arp_header;

		// vreau sa vad daca e pentru mine
		uint8_t *router_mac = malloc(6 * sizeof(uint8_t));
		get_interface_mac(interface, router_mac);  // iau mac-ul routerului
		char *auxiliar = get_interface_ip(interface);
		int router_ip = inet_addr(auxiliar);  // iau ip-ul routerului

		// compar mac-ul routerului meu cu mac-ul destinatarului
		int ok = 1, broadcast = 1;
		for (int i = 0; i < 6; i++) {
			if (eth_hdr->ether_dhost[i] != *(router_mac + i)) ok = 0;
			if (eth_hdr->ether_dhost[i] != 0xff) broadcast = 0;
		}

		if (!ok && !broadcast) {  // nu este pentru mine
			// arunca pachetul
			continue;
		} else {  // este pentru mine => forwarding
			// vad ce ether_type am
			if (ntohs(eth_hdr->ether_type) == 0x0800) {  // am IPv4
				iphdr = (struct iphdr*) (buf + sizeof(*eth_hdr));
				printf("SUNTEM IN IPv4\n");

				// verific daca checksum e bun
				if (checksum((void*)iphdr, sizeof(struct iphdr)) != 0) {
					// arunca pachetul
					continue;
				} else {
					// verific daca mai are timp de viata
					if (iphdr->ttl == 1 || iphdr->ttl == 0) {
						// arunca pachetul
						send_icmp(eth_hdr, iphdr, 11, router_ip, interface);
						continue;
					} else {
						// scad din timpul de viata
						iphdr->ttl--;

						// actualizare checksum
						iphdr->check = ~(~iphdr->check + ~((uint16_t)(iphdr->ttl + 1)) + (uint16_t)iphdr->ttl) - 1;

						// vad daca routerul este destinatie
						if(iphdr->daddr == router_ip) {  // routerul meu e destinatia
							// trimit ICMP reply
							send_icmp(eth_hdr, iphdr, 0, router_ip, interface);
							continue;
						} else {  // nu routerul meu e destinatia
							// caut in tabela de rutare urmatorul hop
							struct route_table_entry* best_route = get_best_route(root, iphdr->daddr);
							if (best_route == NULL) {
								send_icmp(eth_hdr, iphdr, 3, router_ip, interface);
								continue;
							} else {  
								// schimbare adrese de mac
								// routerul meu devine noua sursa
								// best_route devine noua destinatie

								// caut sa vad daca am mac-ul destinatiei salvat in cache
								struct arp_entry *mac_from_cache = get_mac_from_cache(best_route);
								if (mac_from_cache != NULL) {  // aveam deja mac-ul salvat in cache
									memcpy(&eth_hdr->ether_shost, router_mac, 6 * sizeof(uint8_t));
									memcpy(&eth_hdr->ether_dhost, mac_from_cache->mac, 6 * sizeof(uint8_t));
									send_to_link(best_route->interface, buf, len);
								} else { // nu am mac-ul in cache
									// salvez pachetul actual in coada si il pun pe standby pana primeste raspuns
									struct packet *p = malloc(sizeof(struct packet));
									memcpy(p->buffer, buf, len);
									p->len = len;
									p->best_route = best_route;
									queue_enq(packets, (void*) p);

									// fac un pachet ca sa trimit request de mac in broadcast
									void* buffer = calloc(1, sizeof(struct ether_header) + sizeof(struct arp_header));

									// ether header
									get_interface_mac(best_route->interface, router_mac);
									struct ether_header *eth_hdr_broadcast = (struct ether_header *) buffer;
									memset(eth_hdr_broadcast->ether_dhost, 0xff, 6);
									memcpy(eth_hdr_broadcast->ether_shost, router_mac, 6);
									eth_hdr_broadcast->ether_type = 0x0608;

									// scot ip router
									char *aux = get_interface_ip(best_route->interface);
									int ip = inet_addr(aux);

									// arp header
									struct arp_header *arp = (struct arp_header *) (buffer + sizeof(struct ether_header));
									arp->op = htons(1);
									arp->htype = htons(1);
									arp->hlen = 6;
									arp->plen = 4;
									arp->ptype = 0x0008;
									memcpy(arp->sha, router_mac, 6);
									arp->spa = ip;
									memset(arp->tha, 0, 6);
									arp->tpa = best_route->next_hop;
									send_to_link(best_route->interface, buffer, sizeof(struct ether_header) + sizeof(struct arp_header));
								}
							}
						}
					}
				}
			} else if (ntohs(eth_hdr->ether_type) == 0x0806) {  // am ARP
				struct ether_header* eh = (struct ether_header*) buf;
				arp_header = (struct arp_header*) (buf + sizeof(struct ether_header));
				printf("avem ARP\n");

				if (arp_header->op == htons(2)) {  // am primit reply
					// vreau sa scot toate pachetele din coada care asteapta pentru mac-ul primit si sa le trimit
					int packets_len = packets->length;
					while (packets_len) {
						struct packet *first = (struct packet*) queue_deq(packets);
						// verific daca ip-ul la care trebuie trimise pachetele din coada este acelasi cu ce am primit acum
						if(first->best_route->next_hop == arp_header->spa) {
							struct ether_header* aux = (struct ether_header*) first->buffer;
							memcpy(aux->ether_shost, router_mac, 6);
							memcpy(aux->ether_dhost, arp_header->sha, 6);
							send_to_link(first->best_route->interface, first->buffer, first->len);
						} else {
							queue_enq(packets, (void*) first);
						}

						packets_len--;
					}

					// pune mac-ip in cache
					struct arp_entry *arp = calloc(1, sizeof(struct arp_entry));
					arp->ip = arp_header->spa;
					memcpy(arp->mac, arp_header->sha, 6);
					queue_enq(cache_queue, (void*) arp);
				} else {  // am primit request
					printf("arp request");
					// trebuie sa dau mac-ul meu

					memcpy(eh->ether_dhost, eh->ether_shost, 6);
					memcpy(eh->ether_shost, router_mac, 6);

					char *aux = get_interface_ip(interface);
					int ip = inet_addr(aux);
					arp_header->tpa = arp_header->spa;
					arp_header->spa = ip;
					memcpy(arp_header->tha, arp_header->sha, 6);
					memcpy(arp_header->sha, router_mac, 6);
					arp_header->op = htons(2);

					send_to_link(interface, buf, len);
				}
			}
		}
	}
}

