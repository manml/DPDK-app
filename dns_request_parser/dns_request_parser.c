/* 
This application only for parsing DNS domain from UDP DNS qeury and printing the domain.
 */

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>


#define ENABLE_SEND		1
#define ENABLE_ARP		1


//Setup memory buffers for memory pool.
#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32


// setup NIC number
int gDpdkPortId = 0;



static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

//initiate the NIC with allocated memory pool.
static void ng_init_port(struct rte_mempool *mbuf_pool) {

	// check if NIC has been bound with DPDK
	uint16_t nb_sys_ports= rte_eth_dev_count_avail(); 
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	//NIC info struct
	struct rte_eth_dev_info dev_info;

	// Get raw NIC info via a function provided by DPDK
	rte_eth_dev_info_get(gDpdkPortId, &dev_info); 
	printf("Dev info\n driver_name : %s\n if_index: %d\n mtu: %d %d\n Queue: %d %d\n", dev_info.driver_name,dev_info.if_index,dev_info.max_mtu,dev_info.min_mtu,dev_info.nb_rx_queues,dev_info.nb_tx_queues);


	// Setuo rx & tx queue for NIC
	const int num_rx_queues = 1;
	const int num_tx_queues = 1;

	//NIC configuration struct
	struct rte_eth_conf port_conf = port_conf_default;
	//Configure the NIC with queue parameters
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);


	//1024 is uint16_t nb_rx_desc , it stands for the length of the rx queue. 1024 packets
	if (rte_eth_rx_queue_setup(gDpdkPortId, 0 , 1024, 
		rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {

		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

	}

	//Start the NIC
	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

	

}


static int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {

	// encode 

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udp+1), data, udplen);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	return 0;
}


static struct rte_mbuf * ng_send(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {

	// mempool --> mbuf

	const unsigned total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_pkt(pktdata, data, total_len);

	return mbuf;

}

int main(int argc, char *argv[]) {

/* 
RunTime Environment RTE
Environment Abstraction Layer EAL
initiate the environment. EAL is a interface that connect application and hardware.
verify hugepages
*/
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
		
	}
/* 
Memory pool. It is used to store data received on the NIC.
one process -> on pool
Create memory pool by call rte_pktmbuf_pool_create
 */
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

//initiate the NIC
	ng_init_port(mbuf_pool);

	while (1) {

		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
	
		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}

			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			
			if (iphdr->next_proto_id == IPPROTO_UDP) {

				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

				uint16_t length = ntohs(udphdr->dgram_len);
				*((char*)udphdr + length) = '\0';

				printf("Length of UDP: %d\n", length);
				unsigned char domain[128], *dns = domain;
				unsigned char *pp = udphdr;
				pp += 8; /* Move to DNS from UDP header  */
				pp += 4; /* Move to Question in DNS Query */
				int question = ntohs(*((unsigned short*)pp));
				printf("Question: %d\n",question);
				pp += 8; /* Move to Query in DNS Query */
				bzero(domain , sizeof(domain));
				for (;;){
						unsigned short t = (int)pp[0];
						pp ++;
						if (t == 0)
							break;
						rte_memcpy(dns , pp , t);
						dns += t;
						pp += t;
						if((int)pp[0] != 0)
							rte_memcpy(dns , "." , 1);
						dns ++;
					}
				printf("Domain: %s\n",domain);
				printf("-------------------------------\n");
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

				addr.s_addr = iphdr->dst_addr;
				printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(udphdr->dst_port));

				rte_pktmbuf_free(mbufs[i]);
			}
			
		}

	}

}
