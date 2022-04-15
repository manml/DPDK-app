#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

//Setup memory buffers for memory pool.
#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32

const char *A_RECORD = "1.1.1.1";

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

int main(int argc, char *argv[]) {

	/* 
RunTime Environment RTE
Environment Abstraction Layer EAL
initiate the environment. EAL is a interface that connect application and hardware.
verify hugepages
*/
	if (rte_eal_init(argc, argv) < 0) 
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
		
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
	uint16_t src_port;
	uint16_t dst_port; 
	uint16_t transaction_id;

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
		for (i = 0;i < num_recvd;i ++){
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			
			// if the next header is not IPv4.
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}

			/* Get next IP header.
			The offset means start from offset. Not the lenght.
			*/
			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			if (iphdr->next_proto_id == IPPROTO_UDP){
				/*Get UDP header.
				Two ways:
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)((unsigned char *)iphdr + sizeof(struct rte_ipv4_hdr));
				*/
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
				
				rte_eth_macaddr_get(gDpdkPortId,(struct rte_ether_addr *)srcmac);
				//rte_memcpy(srcmac,ehdr->d_addr.addr_bytes,RTE_ETHER_ADDR_LEN);
				rte_memcpy(dstmac,ehdr->s_addr.addr_bytes,RTE_ETHER_ADDR_LEN);
				//printf("111111\n");
				rte_memcpy(&src_ip,&iphdr->dst_addr,sizeof(uint32_t));
				rte_memcpy(&dst_ip,&iphdr->src_addr,sizeof(uint32_t));
				//printf("2222222\n");
				rte_memcpy(&src_port,&udphdr->dst_port,sizeof(uint32_t));
				rte_memcpy(&dst_port,&udphdr->src_port,sizeof(uint32_t));
				//src_port = ntohs(udphdr->dst_port);
				//dst_port = ntohs(udphdr->src_port);
				printf("SrcPort: %d\n",ntohs(src_port));
				printf("DstPort: %d\n",ntohs(dst_port));

				// Length in UDP header means all payload + UDP header
				uint16_t length = ntohs(udphdr->dgram_len);
				//*((char*)udphdr + length) = '\0';

				printf("Length of UDP: %d\n", length);
				//printf("Data: %s\n", (unsigned char *)udphdr +1);
				unsigned char domain[128], *dns = domain;
				unsigned char *pp = rte_pktmbuf_mtod_offset(mbufs[i],unsigned char *,42);
				//pp += 8; /* Move to DNS  */
				transaction_id = ntohs(*((unsigned short*)pp));
				printf("Transaction_id: %d\n",transaction_id);
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
				printf("Domain: %s, length is %ld\n",domain, strlen((char *)domain)+2);
				printf("-------------------------------\n");

				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("Src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));
				
				addr.s_addr = iphdr->dst_addr;
				printf("Dst: %s:%d\n", inet_ntoa(addr), ntohs(udphdr->dst_port));




				/* 
				Build a DNS response
				 */	

				/* For example, a.mmlnp.com -> 1.1.1.1
				Query: a.mmlnp.com
				Answer: a.mmlnp.com + 1.1.1.1
				Length of the first "a.mmlnp.com" is 13 Bytes.(11+2) First Byte = label count. Last Byte = 00;
				Other "a.mmlnp.com" is 2 Bytes :pointer that point to the first
				1.1.1.1  -> 4 Bytes

				Before we construct a packet we need calculate the length of it.

				Transaction_id 2
				Flags 2
				Questions summary 2
				Answer summary 2
				Authority RR 2
				Additional RR 2
				Query: Name(domain_len)+ type 2 + class 2
				Answer: Name(pointer(2)) +Type 2 + class 2 + TTL 4 + Data length 2 + Value(4 for IP address)
				*/

				// This is DNS part length.
				const unsigned dns_len = 34 + strlen((char *)domain);
				printf("Length of domain %ld\n", strlen((char *)domain));

				//This is total length
				const unsigned total_len = dns_len + 8 + 20 + 14;

				//Allocate a new mbuf from a mempool.
				struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool); // This line cause src ip is wrong
				if (!mbuf){
					rte_exit(EXIT_FAILURE, "Not able to allocate mbuf\n");
				}
				mbuf->data_len = total_len;
				mbuf->pkt_len = total_len;
				// Pointer -> start of the mbuf.  Type 1 byte.
				uint8_t *pkt = rte_pktmbuf_mtod(mbuf, uint8_t*);

				//Layer2 build
				struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
				rte_memcpy(eth->s_addr.addr_bytes,srcmac,RTE_ETHER_ADDR_LEN);
				rte_memcpy(eth->d_addr.addr_bytes,dstmac,RTE_ETHER_ADDR_LEN);
				eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

				//Layer3 build
				struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt + sizeof(struct rte_ether_hdr));
				// version and header
				ip->version_ihl = 0x45;
				ip->type_of_service = 0;
				ip->total_length = htons(dns_len+28);
				ip->packet_id = 0;
				ip->fragment_offset = 0;
				ip->time_to_live = 255;
				ip->next_proto_id = IPPROTO_UDP;
				ip->src_addr = iphdr->dst_addr;
				ip->dst_addr = iphdr->src_addr;
				//Initate checksum to 0 to prevent on premise value of checksum in the calculation.
				ip->hdr_checksum = 0;

				//Layer4 build
				struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(pkt+ sizeof(struct  rte_ether_hdr) + sizeof(struct  rte_ipv4_hdr));
				udp->src_port = udphdr->dst_port;
				udp->dst_port = udphdr->src_port;
				udp->dgram_len = htons(dns_len+8);
				udp->dgram_cksum = 0;
				

				addr.s_addr = iphdr->dst_addr;
				printf("Response src: %s:%d, ", inet_ntoa(addr), ntohs(udp->src_port));

				addr.s_addr = ip->dst_addr;
				printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(udp->dst_port));

				//DNS build
				unsigned char *presend = rte_pktmbuf_mtod_offset(mbuf,unsigned char *,42);
				//Move to DNS and set transaction ID
				*(unsigned short *)presend = htons(transaction_id);
				//Move to Flags
				presend += 2;
				*(unsigned short *)presend = htons(0x8180);
				//Move to Question
				presend += 2;
				*(unsigned short *)presend = htons(1);
				//Move to Answer
				presend += 2;
				*(unsigned short *)presend = htons(1);
				//Move to Authority RR
				presend += 2;
				*(unsigned short *)presend = 0;
				//Move to Additional RR
				presend += 2;
				*(unsigned short *)presend = 0;
				//Move to Query Domain name
				presend += 2;
				unsigned char *qq = (unsigned char *)udphdr;
				qq += 20;
				rte_memcpy(presend,qq,strlen((char *)domain)+2);
				//rte_memcpy(presend,domain,strlen(domain)+2);
				// Move to Type
				presend = presend + strlen((char *)domain)+2;
				*(unsigned short *)presend = htons(1);
				//Move to Class
				presend += 2;
				*(unsigned short *)presend = htons(1);
				//Move to Answer
				presend += 2;
				*(unsigned short *)presend = htons(0xc00c);  //Pointer -> domain in Query
				presend += 2;
				*(unsigned short *)presend = htons(1);  // Type -> A
				presend += 2;
				*(unsigned short *)presend = htons(1); // Class
				presend += 2;
				*(unsigned int *)presend = htonl(600); // TTL
				presend += 4;
				*(unsigned short *)presend = htons(4); // RDLENGTH
				presend += 2;
				inet_aton(A_RECORD,&addr);
				printf("IP: %s, length is %ld\n",A_RECORD, strlen(A_RECORD));
				rte_memcpy(presend,&addr.s_addr,INET_ADDRSTRLEN); // RDATA

				udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip,udp);
				ip->hdr_checksum = rte_ipv4_cksum(ip);
				printf("Constructing completed!\n");


				//Send packet
				uint16_t num = rte_eth_tx_burst(gDpdkPortId,0,&mbuf,1);
				printf("%d packets has been sent\n", num);
				rte_pktmbuf_free(mbuf);

				//Free a packet mbuf back into its original mempool.
				rte_pktmbuf_free(mbufs[i]);
			}	
		}

	}
}