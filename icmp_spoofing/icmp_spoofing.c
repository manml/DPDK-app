#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>



//Setup memory buffers for memory pool.
#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32


// setup NIC number
int gDpdkPortId = 0;


//
static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

//initiate the NIC with allocated memory pool.
static void init_port(struct rte_mempool *mbuf_pool) {

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
		//When receiving data from interface, the data will be stored at this mbuf_pool
		rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}

	//set up configuration for tx
	struct rte_eth_txconf tx_conf = dev_info.default_txconf;
	//set up tx offload which is size of data transfer
	tx_conf.offloads = port_conf_default.rxmode.offloads;
	printf("Offload: %d\n", (int)tx_conf.offloads);
	if (rte_eth_tx_queue_setup(gDpdkPortId, 0 , 1024, 
		//TX queue
		rte_eth_dev_socket_id(gDpdkPortId), &tx_conf) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}

	//Start the NIC
	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

}

static uint16_t checksum(uint16_t *addr, int count) {

	register long sum = 0;

	while (count > 1) {

		sum += *(unsigned short*)addr++;
		count -= 2;
	
	}

	if (count > 0) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
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
	init_port(mbuf_pool);

	uint8_t srcmac[RTE_ETHER_ADDR_LEN];
	uint8_t dstmac[RTE_ETHER_ADDR_LEN];
	uint32_t src_ip;
	uint32_t dst_ip;

	while (1) {
		
		struct rte_mbuf *mbufs[BURST_SIZE];
		// get data from interface / queue / memory buffer / receive size
		//mbufs -> mbuf_pool in setup rx 
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
	
		/* 
		Basically it will be 1 packet. That means num_recevd = 1.
		 */
		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {

			// Convert the buffer into Ethernet header
			struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			
			// if the next header is not IPv4.
			if (ethhdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}

			/* Get next IP header.
			The offset means start from offset. Not the lenght.
			*/
			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));

			/* Get next ICMP header.
			The offset means start from offset. Not the lenght.
			*/
			if (iphdr->next_proto_id != IPPROTO_ICMP ){
				continue;
			}

			/*struct rte_icmp_hdr *icmphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_icmp_hdr *, 
				(sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)));
			*/
			struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
			rte_memcpy(dstmac, ethhdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
			rte_memcpy(srcmac, ethhdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
			rte_memcpy(&src_ip,&iphdr->dst_addr,sizeof(uint32_t));
			rte_memcpy(&dst_ip,&iphdr->src_addr,sizeof(uint32_t));
			struct in_addr addr;
			addr.s_addr = iphdr->src_addr;
			printf("Request src: %s \n", inet_ntoa(addr));

			//  ####How to print MAC address?

			//PING echo
			if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST){

				const unsigned total_length = sizeof(struct rte_ether_hdr) + ntohs(iphdr->total_length);
				
				struct rte_mbuf *icmpbuf  = rte_pktmbuf_alloc(mbuf_pool);
				if (!icmpbuf) {
					rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
				}
				icmpbuf->pkt_len = total_length;
				icmpbuf->data_len = total_length;

				uint8_t *pkt_data = rte_pktmbuf_mtod(icmpbuf, uint8_t *);

				//Ethernet
				uint8_t srcmac[RTE_ETHER_ADDR_LEN];
				rte_eth_macaddr_get(gDpdkPortId,(struct rte_ether_addr *)srcmac);
				struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;
				rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
				rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
				eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

				//IP
				struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt_data + sizeof(struct rte_ether_hdr));
				ip->version_ihl = 0x45;
				ip->type_of_service = 0;
				printf("Total size: %d\n",total_length);
				ip->total_length = iphdr->total_length;
				ip->src_addr = iphdr->dst_addr;
				ip->dst_addr = iphdr->src_addr;
				ip->next_proto_id = IPPROTO_ICMP;
				ip->packet_id = iphdr->packet_id;
				ip->fragment_offset = 0;
				ip->time_to_live = 64;

				ip->hdr_checksum = 0;
				ip->hdr_checksum = rte_ipv4_cksum(ip);

				//ICMP
				struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(pkt_data + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
				icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
				icmp->icmp_code = 0;
				icmp->icmp_ident = icmphdr->icmp_ident;
				icmp->icmp_seq_nb = icmphdr->icmp_seq_nb;


				//Copy ICMP data
				unsigned char *a = rte_pktmbuf_mtod_offset(mbufs[i],unsigned char *,42);
				unsigned char *b = rte_pktmbuf_mtod_offset(icmpbuf,unsigned char *,42);
				printf("Data: %s\n",a);
				rte_memcpy(b, a , total_length - 42);

				icmp->icmp_cksum = 0;
				icmp->icmp_cksum = checksum((uint16_t*)icmp, total_length-34 );

				rte_eth_tx_burst(gDpdkPortId, 0, &icmpbuf, 1);
				rte_pktmbuf_free(icmpbuf);

				rte_pktmbuf_free(mbufs[i]);

			}

	}

}
}