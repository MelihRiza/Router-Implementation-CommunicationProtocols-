#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#define ICMP_LEN 42
#define ARP_LEN 42
#define IPV4_LEN 34


struct cacheTableEntry { //STORE DATA FROM ARP REPLIES
	uint32_t ip;
	uint8_t mac[6];
	struct cacheTableEntry *next;
};

struct cacheTableEntry *createCacheTable() {
	struct cacheTableEntry *cache = (struct cacheTableEntry *) malloc(sizeof(struct cacheTableEntry));
	cache->next = NULL;
	return cache;
}

void addToCacheTable(struct cacheTableEntry *cache, uint32_t ip, uint8_t mac[6]) {
	struct cacheTableEntry *temp = cache;
	while (temp->next != NULL) {
		temp = temp->next;
	}
	temp->next = (struct cacheTableEntry *) malloc(sizeof(struct cacheTableEntry));
	temp->next->ip = ip;
	memcpy(temp->next->mac, mac, 6);
	temp->next->next = NULL;
}

struct cacheTableEntry* findInCacheTable(struct cacheTableEntry *cache, uint32_t ip) {
	struct cacheTableEntry *temp = cache;
	while (temp != NULL) {
		if (temp->ip == ip) {
			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}

struct Trie {
	struct route_table_entry element;
	struct Trie *left;
	struct Trie *right;
};


struct Trie *createTrieNode() {
	struct Trie *nod = (struct Trie *) malloc(sizeof(struct Trie));
	nod->left = NULL;
	nod->right = NULL;
	return nod;
}

uint32_t ipToDecimal(char* ip) {

	u_int32_t x = 0;
	u_int32_t k = 0;
	for (int i = 0; i < 4; i++) {
		int j = 0;
		char* temp = (char*) malloc(sizeof(char) * 5);
		while (ip[k] != '.' && ip[k] != '\0') {
			temp[j] = ip[k];
			j++;
			k++;
		}
		k++;
		temp[4] = '\0';
		u_int32_t to_add = (uint32_t)atoi(temp);
		to_add = to_add << ((3 - i) * 8);
		x = x | to_add;
	}

	return x;
}


struct Trie *buildTrie(char* file_to_read) {
	FILE *file = fopen(file_to_read, "r");
	char* route_table_entry = (char *) malloc(sizeof(char) * 49);
	struct Trie *root = createTrieNode();

	while (fgets(route_table_entry, 49, file)) {
		struct route_table_entry entry_element;
		char *prefix = (char*) malloc(sizeof(char) * 15);
		char *nextHop = (char*) malloc(sizeof(char) * 15);
		char *mask = (char*) malloc(sizeof(char) * 15);
		char *interface = (char*) malloc(sizeof(char));

		char *elem;

		elem = strtok(route_table_entry, " ");
		memcpy(prefix, elem, strlen(elem));
		entry_element.prefix = ipToDecimal(prefix);

		elem = strtok(NULL, " ");
		memcpy(nextHop, elem, strlen(elem));
		entry_element.next_hop = ipToDecimal(nextHop);

		elem = strtok(NULL, " ");
		memcpy(mask, elem, strlen(elem));
		entry_element.mask = ipToDecimal(mask);

		elem = strtok(NULL, " ");
		memcpy(interface, elem, strlen(elem));
		entry_element.interface = atoi(interface);


		struct Trie *temp_root = root;
		uint32_t pos = entry_element.mask & entry_element.prefix;
		uint32_t byte_check = 1 << 31;

		while (byte_check) {
			if ((byte_check & pos) == 0) {
				if (root->left) {
					root = root->left;
				} else {
					root->left = createTrieNode();
					root = root->left;
				}
				byte_check >>= 1;
				if ((entry_element.mask & byte_check) == 0) {
					root->element = entry_element;
					root = temp_root;
					break;
				}
			} else {
				if (root->right) {
					root = root->right;
				}else {
					root->right = createTrieNode();
					root = root->right;
				}
				byte_check >>= 1;
				if ((entry_element.mask & byte_check) == 0) {
					root->element = entry_element;
					root = temp_root;
					break;
				}
			}
		}

		free(prefix);
		free(nextHop);
		free(mask);
		free(interface);
	}

	return root;
}


struct route_table_entry getRouteTableEntry(struct Trie *root, uint32_t ip) {
	u_int32_t byte_check = 1 << 31;
	struct Trie *temp_node = root;
	struct Trie *res = createTrieNode();
	res->left = NULL;
	res->right = NULL;

	while (byte_check != 0) {
		if ((byte_check & ip) == 0) {
			if (temp_node->left == NULL) {
				res = temp_node;
				break;
			}
			temp_node = temp_node->left;
		} else {
			if (temp_node->right == NULL) {
				res = temp_node;
				break;
			}
			temp_node = temp_node->right;
		}
		byte_check >>= 1;
	}
	
	return temp_node->element;
}



int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);


	struct Trie* rootTrie = buildTrie(argv[1]);
	struct cacheTableEntry* cache_table = createCacheTable();
	struct queue *packets_queue = queue_create();


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


		if (ntohs(eth_hdr->ether_type) == 0x0800) {  //RECEIVERD IPv4 PACKET
			struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

			if (ntohl(ip_hdr->daddr) == ipToDecimal(get_interface_ip(interface))) {	//ICMP "echo request" FOR ROUTER. RESPOND WITH "echo reply".
				struct route_table_entry entry_table = getRouteTableEntry(rootTrie, ntohl(ip_hdr->saddr));
				struct icmphdr* icmp_response = (struct icmphdr*) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));
				icmp_response->code = 0;
				icmp_response->type = 0;
				icmp_response->un.echo.id = htons(0);
				icmp_response->un.echo.sequence = htons(0);
				icmp_response->checksum = 0;
				icmp_response->checksum = htons(checksum((u_int16_t *) icmp_response, sizeof(struct icmphdr)));
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				u_int8_t mac[6];
				get_interface_mac(interface, mac);
				memcpy(eth_hdr->ether_shost, mac, 6);
				send_to_link(entry_table.interface, buf, ICMP_LEN);

			} else {
				u_int16_t temp_checksum = ntohs(ip_hdr->check);
				ip_hdr->check = 0;
		
				if (temp_checksum == checksum((uint16_t *) ip_hdr, sizeof(struct iphdr))) {
					if (ip_hdr->ttl > 1) {
						ip_hdr->ttl--;
						ip_hdr->check = 0;
						ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));
						
						struct route_table_entry entry_table = getRouteTableEntry(rootTrie, ntohl(ip_hdr->daddr));
						struct cacheTableEntry *get_from_cache = findInCacheTable(cache_table, htonl(entry_table.next_hop));

						if (entry_table.next_hop == 0) {  //HOST UNREACHABLE => ICMP UNREACHABLE MESSAGE

							struct iphdr* old_ip_hdr = (struct iphdr*)malloc(sizeof(struct iphdr));
							char* payload_64 = (char*) malloc(sizeof(char) * 8);

							memcpy(old_ip_hdr, buf + sizeof(struct ether_header), sizeof(struct iphdr));
							memcpy(payload_64, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);


							struct icmphdr* icmp_hdr = (struct icmphdr*) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
							struct iphdr* ip_hdr = (struct iphdr*) (buf + sizeof(struct ether_header));
							icmp_hdr->code = 0;
							icmp_hdr->type = 3;
							icmp_hdr->un.echo.id = htons(0);
							icmp_hdr->un.echo.sequence = htons(0);
							icmp_hdr->checksum = 0;
							icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmphdr)));
							ip_hdr->protocol = 1;
							int sender = ip_hdr->saddr;
							int destination = ip_hdr->daddr;
							ip_hdr->saddr = destination;
							ip_hdr->daddr = sender;
							ip_hdr->tot_len = htons(28);
							memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
							u_int8_t mac[6];
							get_interface_mac(interface, mac);
							memcpy(eth_hdr->ether_shost, mac, 6);

							//ADD THE DROPPED IPV4 AND THE 64 BITS OF THE INITIAL PAYLOAD
							memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), old_ip_hdr, sizeof(struct iphdr));
							memcpy(buf + sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr), payload_64, 8);

							send_to_link(interface, buf, ICMP_LEN + sizeof(struct iphdr) + 8);
						}
						else {
							if (get_from_cache == NULL) { // MAC ADDRESS DOES NOT EXIST IN CACHE_TABLE

								// ENQUEUE THE CURRENT ARRIVED PACKET
								char* temp = (char *) malloc(1600 * sizeof(char));
								for (int i = 0; i < len; i++) {
									temp[i] = buf[i];
								}
								queue_enq(packets_queue, temp);	
									

								//SEND ARP REQUEST
										
								char* send_request = (char *) malloc(1600 * sizeof(char));
								struct ether_header *eth_hdr_request = (struct ether_header *) send_request;
								struct arp_header *arp_hdr_request = (struct arp_header *) (send_request + sizeof(struct ether_header));
								eth_hdr_request->ether_type = htons(0x0806);
								u_int8_t mac[6];
								get_interface_mac(entry_table.interface, mac);
								memcpy(eth_hdr_request->ether_shost, mac, 6);
								memset(eth_hdr_request->ether_dhost, 0xFF, 6);
								arp_hdr_request->htype = htons(0x0001);
								arp_hdr_request->ptype = htons(0x0800);
								arp_hdr_request->hlen = 6;
								arp_hdr_request->plen = 4;
								arp_hdr_request->op = htons(0x0001);
								memcpy(arp_hdr_request->sha, mac, 6);
								arp_hdr_request->spa = htonl(ipToDecimal(get_interface_ip(entry_table.interface)));
								memset(arp_hdr_request->tha, 0x0000, 6);
								arp_hdr_request->tpa = htonl(entry_table.next_hop);

								send_to_link(entry_table.interface, send_request, ARP_LEN);
								
							} else { // MAC ADDRESS EXISTS ALREADY IN CACHE_TABLE
								u_int8_t mac[6];
								get_interface_mac(entry_table.interface, mac);
								memcpy(eth_hdr->ether_shost, mac, 6);
								memcpy(eth_hdr->ether_dhost, get_from_cache->mac, 6);
								send_to_link(entry_table.interface, buf, len);
							}
						}		
					} else {
						// ICMP TIME EXCEEDED
						struct iphdr* old_ip_hdr = (struct iphdr*)malloc(sizeof(struct iphdr));
						char* payload_64 = (char*) malloc(sizeof(char) * 8);

						memcpy(old_ip_hdr, buf + sizeof(struct ether_header), sizeof(struct iphdr));
						memcpy(payload_64, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

						struct icmphdr* icmp_hdr = (struct icmphdr*) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
						struct iphdr* ip_hdr = (struct iphdr*) (buf + sizeof(struct ether_header));
						icmp_hdr->code = 0;
						icmp_hdr->type = 11;
						icmp_hdr->un.echo.id = htons(0);
						icmp_hdr->un.echo.sequence = htons(0);
						icmp_hdr->checksum = 0;
						icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmphdr)));
						ip_hdr->protocol = 1;
						int sender = ip_hdr->saddr;
						int destination = ip_hdr->daddr;
						ip_hdr->saddr = destination;
						ip_hdr->daddr = sender;
						ip_hdr->tot_len = htons(28);

						//ADD THE DROPPED IPV4 AND THE 64 BITS OF THE INITIAL PAYLOAD
						memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), old_ip_hdr, sizeof(struct iphdr));
						memcpy(buf + sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr), payload_64, 8);

						send_to_link(interface, buf, ICMP_LEN + sizeof(struct iphdr) + 8);
					}
				} else {
						//DROP THE PACKET WRONG CHECKSUM
				}
			}
		} else if (ntohs(eth_hdr->ether_type) == 0x0806) { // RECEIVERD APR PACKET
			struct arp_header *arp_hdr1 = (struct arp_header *) (buf + sizeof(struct ether_header));
			
			if (ntohs(arp_hdr1->op) == 0x0002) { //RECEIVED ARP REPLY

				while (!queue_empty(packets_queue)) {
					char* further_to_send = (char *) malloc(1600 * sizeof(char));
					further_to_send = queue_deq(packets_queue);
					struct iphdr* ip_hdr_to_send = (struct iphdr *) (further_to_send + sizeof(struct ether_header));
					struct route_table_entry entry_table = getRouteTableEntry(rootTrie, ntohl(ip_hdr_to_send->daddr));
					struct ether_header *eth_hdr_send = (struct ether_header *) further_to_send;
					memcpy(eth_hdr_send->ether_dhost, arp_hdr1->sha, 6);
					memcpy(eth_hdr_send->ether_shost, arp_hdr1->tha, 6);

					send_to_link(entry_table.interface, further_to_send, IPV4_LEN);
					
					//STORE THE RECEIVED MAC AND IP IN THE CACHE_TABLE
					addToCacheTable(cache_table, ntohl(entry_table.next_hop), arp_hdr1->sha);
				}

			} else if (ntohs(arp_hdr1->op) == 0x0001) {  //RECEIVED ARP REQUEST

				struct route_table_entry entry_table = getRouteTableEntry(rootTrie, ntohl(arp_hdr1->spa));

				char* send_response = (char *) malloc(1600 * sizeof(char));
				struct ether_header *eth_hdr_response = (struct ether_header *) send_response;
				struct arp_header *arp_hdr_response = (struct arp_header *) (send_response + sizeof(struct ether_header));
				eth_hdr_response->ether_type = htons(0x0806);

				u_int8_t mac[6];
				get_interface_mac(entry_table.interface, mac);
				memcpy(eth_hdr_response->ether_shost, mac, 6);
				memcpy(eth_hdr_response->ether_dhost, eth_hdr->ether_shost, 6);

				arp_hdr_response->htype = htons(0x0001);
				arp_hdr_response->ptype = htons(0x0800);
				arp_hdr_response->hlen = 6;
				arp_hdr_response->plen = 4;
				arp_hdr_response->op = htons(0x0002);
				memcpy(arp_hdr_response->sha, mac, 6);
				arp_hdr_response->spa = arp_hdr1->tpa;  
				memcpy(arp_hdr_response->tha, eth_hdr->ether_shost, 6);
				arp_hdr_response->tpa = htonl(entry_table.next_hop);

				send_to_link(entry_table.interface, send_response, ARP_LEN);
			}
		}	
	}
}

