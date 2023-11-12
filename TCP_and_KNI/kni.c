#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_malloc.h>
#include <rte_kni.h>
#include <rte_log.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

//Setup memory buffers for memory pool.
#define NUM_MBUFS (4096-1)

#define BURST_SIZE	256
#define RING_SIZE	1024
#define TCP_MAX_SEQ		4294967295
#define TCP_OPTION_LENGTH	10
#define TCP_INITIAL_WINDOW  14600

#define ENABLE_KNI 1
#define ENABLE_TCP 1


#define MAX_PACKET_SZ           2048
/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

// setup NIC number
int DpdkPortId = 0;
int fd = 0;
struct rte_kni *global_kni = NULL;

struct inout_ring {

	struct rte_ring *in;
	struct rte_ring *out;
};

static struct inout_ring *rInst = NULL;

static struct inout_ring *ringInstance(void) {

	if (rInst == NULL) {

		rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
		memset(rInst, 0, sizeof(struct inout_ring));
	}

	return rInst;
}

#if ENABLE_TCP 

typedef enum TCP_STATE{
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,	/* Now a valid state */
	TCP_NEW_SYN_RECV, /* Not used in this case */

	TCP_MAX_STATES	/* Leave at the end! */
}TCP_STATE;

struct tcp_fragment { 

	uint16_t srcport;  
	uint16_t dstport;  
	uint32_t seq;  
	uint32_t ack;  
	uint8_t  offset;  
	uint8_t  tcp_flags; 
	uint16_t windows;   
	uint16_t cksum;     
	uint16_t tcp_urp;  

	int optlen;
	uint32_t option[TCP_OPTION_LENGTH];

	unsigned char *data;
	int length;

};


struct tcp_stream{
	int fd;
	uint32_t srcip;
	uint32_t dstip;
	uint16_t srcport;
	uint16_t dstport;
	uint16_t protocol;
	uint32_t send_next; // seq
	uint32_t recv_next; // ack
	TCP_STATE state;
	struct rte_ring *sendbuffer;
	struct rte_ring *recvbuffer;
	struct tcp_stream *prev;
	struct tcp_stream *next;
};

struct tcp_table {
	int count;
	struct tcp_stream *tcb_set;
};

struct tcp_table *tInst = NULL;

static struct tcp_table *tcpInstance(void) {

	if (tInst == NULL) {

		tInst = rte_malloc("tcp_table", sizeof(struct tcp_table), 0);
		memset(tInst, 0, sizeof(struct tcp_table));
		
	}
	return tInst;
}

static struct tcp_stream * tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport){
	struct tcp_table *table = tcpInstance();
	struct tcp_stream *dummy;
	for (dummy = table->tcb_set; dummy != NULL; dummy = dummy->next){
		if (dummy->srcip == sip && dummy->dstip == dip && dummy->srcport == sport &&  dummy->dstport == dport){
			return dummy;
		}
	}
	return NULL;
}

static struct tcp_stream * tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
	struct tcp_stream *stream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
	if (stream == NULL) return NULL;
	stream->srcip = sip;
	stream->dstip = dip;
	stream->srcport = sport;
	stream->dstport = dport;
	stream->protocol = IPPROTO_TCP;
	stream->state = TCP_LISTEN;
	if (fd>65535) fd = 1;
	stream->fd = fd;
	char strfd[20];
	sprintf(strfd, "%dsend", fd);
	stream->sendbuffer = rte_ring_create(strfd, RING_SIZE, rte_socket_id(), 0);
	sprintf(strfd, "%drecv", fd);
	stream->recvbuffer = rte_ring_create(strfd, RING_SIZE, rte_socket_id(), 0);
	fd = fd+1;
	//seq
	uint32_t seed = time(NULL);
	stream->send_next = rand_r(&seed) % TCP_MAX_SEQ;

	struct tcp_table *table = tcpInstance();
	stream->prev = NULL;				
	stream->next = table->tcb_set;				
	if (table->tcb_set != NULL) table->tcb_set->prev = stream; 
	table->tcb_set = stream;	
	return stream;
}

static int tcp_listen_process(struct tcp_stream *stream, struct rte_tcp_hdr *tcp_header){
	if (tcp_header-> tcp_flags & RTE_TCP_SYN_FLAG){
		struct tcp_fragment *fragment = rte_malloc("tcp_fragment",sizeof(struct tcp_fragment),0);
		if (fragment==NULL) return -1;
		memset(fragment,0,sizeof(struct tcp_fragment));
		fragment->srcport = tcp_header->dst_port;
		fragment->dstport = tcp_header->src_port;

		fragment->seq = stream->send_next;
		fragment->ack = ntohl(tcp_header->sent_seq)+1;
		stream->recv_next = fragment->ack;
		fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
		fragment->windows = TCP_INITIAL_WINDOW;

		//pending calculate
		fragment->offset= 0x50;
		fragment->data = NULL;
		fragment->length = 0;
		
		rte_ring_mp_enqueue(stream->sendbuffer,fragment);
		stream->state = TCP_SYN_RECV;
		printf("TCP stream in SYN_Recv:  ");
		struct in_addr addr;
		addr.s_addr = stream->srcip;
		printf("%s:%d ", inet_ntoa(addr), ntohs(tcp_header->src_port));
		addr.s_addr = stream->dstip;
		printf("  --- %s:%d \n", inet_ntoa(addr), ntohs(tcp_header->dst_port));

	}
	return 0;
}

static int tcp_syn_recv_process(struct tcp_stream *stream, struct rte_tcp_hdr *tcp_header){
	if (tcp_header->tcp_flags &  RTE_TCP_ACK_FLAG){
		uint32_t seq = ntohl(tcp_header->sent_seq);
		if (seq==stream->recv_next){
			stream->state = TCP_ESTABLISHED;
			///stream->send_next = ntohl(tcp_header->recv_ack);
			printf("TCP stream in Established:  ");
			struct in_addr addr;
			addr.s_addr = stream->srcip;
			printf("%s:%d ", inet_ntoa(addr), ntohs(tcp_header->src_port));
			addr.s_addr = stream->dstip;
			printf("  --- %s:%d \n", inet_ntoa(addr), ntohs(tcp_header->dst_port));
		}
	}
	return 0;
}

static int tcp_established_process(struct tcp_stream *stream, struct rte_tcp_hdr *tcp_header,int tcplen){
	if (tcp_header->tcp_flags & RTE_TCP_FIN_FLAG){
		// ACK + FIN  so we skip Close-wait
		struct tcp_fragment *fragment = rte_malloc("fin fragment",sizeof(struct tcp_fragment),0);
		if (fragment==NULL) return -1;
		memset(fragment,0,sizeof(struct tcp_fragment));
		fragment->srcport = tcp_header->dst_port;
		fragment->dstport = tcp_header->src_port;
		
		struct in_addr addr;
		addr.s_addr = stream->srcip;
		printf("TCP Receive FIN: src: %s:%d ", inet_ntoa(addr), ntohs(tcp_header->src_port));
		addr.s_addr = stream->dstip;
		printf("  ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(tcp_header->dst_port));

		fragment->tcp_flags = (RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG);
		fragment->windows = TCP_INITIAL_WINDOW;
		fragment->offset = 0x50;
		//fragment->seq = stream->send_next;
		fragment->seq = ntohl(tcp_header->recv_ack);
		fragment->ack = stream->recv_next+1;

		fragment->data=NULL;
		fragment->length=0;
		rte_ring_mp_enqueue(stream->sendbuffer,fragment);
		stream->state = TCP_LAST_ACK;
	}

	if (tcp_header->tcp_flags & RTE_TCP_PSH_FLAG){

		// receive data
		struct tcp_fragment *fragment = rte_malloc("tcp fragment",sizeof(struct tcp_fragment),0);
		if (fragment==NULL) return -1;
		memset(fragment,0,sizeof(struct tcp_fragment));

		fragment->srcport = tcp_header->dst_port;
		fragment->dstport = tcp_header->src_port;

		struct in_addr addr;
		addr.s_addr = stream->srcip;
		printf("TCP Data receive: src: %s:%d ", inet_ntoa(addr), ntohs(tcp_header->src_port));
		addr.s_addr = stream->dstip;
		printf("  ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(tcp_header->dst_port));

		uint8_t headerlen = tcp_header->data_off >> 2;
		printf("TCP Data header length: %d and ",headerlen);
		int payload_len = tcplen - headerlen;
		if (payload_len > 0){
			uint8_t *payload = (uint8_t*)tcp_header + headerlen;
			fragment->data = rte_malloc("data",payload_len+1,0);
			//fragment->data = rte_malloc("unsigned char *",payload_len+1,0);
			if (fragment->data ==NULL){
				rte_free(fragment);
				return -1;
			}
			memset(fragment->data,0,payload_len+1);
			rte_memcpy(fragment->data, payload,payload_len);
			fragment->length = payload_len;
			printf("Data: %s\n",fragment->data);
			rte_ring_mp_enqueue(stream->recvbuffer,fragment);
		}


		//build ACK
		struct tcp_fragment *ackfragment = rte_malloc("tcp fragment",sizeof(struct tcp_fragment),0);
		if (ackfragment==NULL) return -1;
		memset(ackfragment,0,sizeof(struct tcp_fragment));
		ackfragment->srcport = tcp_header->dst_port;
		ackfragment->dstport = tcp_header->src_port;

		ackfragment->ack = stream->recv_next;
		ackfragment->seq = stream->send_next;

		stream->recv_next = stream->recv_next + payload_len;
		stream->send_next = ntohl(tcp_header->recv_ack);

		ackfragment->tcp_flags = RTE_TCP_ACK_FLAG;
		ackfragment->windows=TCP_INITIAL_WINDOW;
		ackfragment->offset=0x50;
		ackfragment->data=NULL;
		ackfragment->length=0;
		rte_ring_mp_enqueue(stream->sendbuffer,ackfragment);
		

		//build echo: copy data from request and send back
		struct tcp_fragment *echofragment = rte_malloc("tcp fragment",sizeof(struct tcp_fragment),0);
		if (echofragment==NULL) return -1;
		memset(echofragment,0,sizeof(struct tcp_fragment));

		echofragment->srcport = tcp_header->dst_port;
		echofragment->dstport = tcp_header->src_port; 

		echofragment->ack = stream->recv_next;
		echofragment->seq = stream->send_next;

		echofragment->tcp_flags = (RTE_TCP_PSH_FLAG | RTE_TCP_ACK_FLAG);
		echofragment->windows = TCP_INITIAL_WINDOW;
		echofragment->offset = 0x50;
		uint8_t *payload = (uint8_t*)tcp_header + headerlen;
		echofragment->data = rte_malloc("unsigned char *",payload_len,0);
		if (echofragment == NULL){
			rte_free(echofragment);
			return -1;
		}
		memset(echofragment->data,0,payload_len);
		rte_memcpy(echofragment->data,payload,payload_len);
		echofragment->length = payload_len;
		rte_ring_mp_enqueue(stream->sendbuffer,echofragment);
	}

	return 0;
}

static int tcp_last_ack_process(struct tcp_stream *stream, struct rte_tcp_hdr *tcp_header){
	if(tcp_header->tcp_flags & RTE_TCP_ACK_FLAG){
		if(ntohl(tcp_header->sent_seq)==stream->recv_next){
			stream->state = TCP_CLOSE;
			printf("TCP stream in Closed:  ");
			struct in_addr addr;
			addr.s_addr = stream->srcip;
			printf("%s:%d ", inet_ntoa(addr), ntohs(tcp_header->src_port));
			addr.s_addr = stream->dstip;
			printf("  --- %s:%d \n", inet_ntoa(addr), ntohs(tcp_header->dst_port));
			rte_ring_free(stream->sendbuffer);
			rte_ring_free(stream->recvbuffer);

			struct tcp_table *table = tcpInstance();
			if (stream->prev != NULL) stream->prev->next = stream->next;
			if (stream->next != NULL) stream->next->prev = stream->prev;
			if (table->tcb_set == stream) table->tcb_set = stream->next;
			stream->prev = stream->next = NULL;	

			rte_free(stream);
		}
	}
	return 0;
}

static int tcp_process(struct rte_mbuf *mbuf_pool){
	struct rte_ipv4_hdr *ip_header = rte_pktmbuf_mtod_offset(mbuf_pool,struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
	struct rte_tcp_hdr *tcp_header = (struct rte_tcp_hdr *)(ip_header+1);
	//struct rte_tcp_hdr *tcp_header = rte_pktmbuf_mtod_offset(mbuf_pool,struct rte_tcp_hdr*, (sizeof(struct rte_ipv4_hdr)+sizeof(struct rte_ether_hdr)));

	uint16_t tcpchecksum = tcp_header->cksum;
	tcp_header->cksum = 0;
	uint16_t cksum = rte_ipv4_udptcp_cksum(ip_header,tcp_header);
	if (cksum != tcpchecksum){
		printf("cksum: %x, tcp checksum %x\n",cksum,tcpchecksum);
		rte_pktmbuf_free(mbuf_pool);
		return -1;
	}
		
	struct tcp_stream *stream = tcp_stream_search(ip_header->src_addr,ip_header->dst_addr,tcp_header->src_port,tcp_header->dst_port);
	if (stream == NULL){
		//New stream
		rte_pktmbuf_free(mbuf_pool);
		if (!(tcp_header->tcp_flags & RTE_TCP_SYN_FLAG)) return -1;
		stream = tcp_stream_create(ip_header->src_addr,ip_header->dst_addr,tcp_header->src_port,tcp_header->dst_port);
		printf("Create a new TCP stream(Listening):  ");
		struct in_addr addr;
		addr.s_addr = stream->srcip;
		printf("%s:%d ", inet_ntoa(addr), ntohs(tcp_header->src_port));
		addr.s_addr = stream->dstip;
		printf("  --- %s:%d \n", inet_ntoa(addr), ntohs(tcp_header->dst_port));
		if (stream == NULL) return -2;
	}

	switch (stream->state){

		//Client
		case TCP_CLOSE:
			break;
		
		case TCP_LISTEN:
			tcp_listen_process(stream,tcp_header);
			break;
		
		//Client 
		case TCP_SYN_SENT:
			break;
		
		case TCP_SYN_RECV:
			tcp_syn_recv_process(stream,tcp_header);
			break;

		case TCP_ESTABLISHED: {
			int tcplen = ntohs(ip_header->total_length) - sizeof(struct rte_ipv4_hdr);
			tcp_established_process(stream,tcp_header,tcplen);
			break;
		}

		case TCP_FIN_WAIT1:
			break;

		case TCP_FIN_WAIT2:
			break;

		case TCP_TIME_WAIT:
			break;

		case TCP_CLOSE_WAIT:
			break;

		case TCP_LAST_ACK:
			tcp_last_ack_process(stream,tcp_header);
			break;

		case TCP_CLOSING:
			break;

		case TCP_NEW_SYN_RECV:
			break;
		case TCP_MAX_STATES:
			break;
		
	}
	rte_pktmbuf_free(mbuf_pool);
	return 0;
}

static struct rte_mbuf *tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t srcip, uint32_t dstip,struct rte_ether_addr s_addr, struct rte_ether_addr d_addr, struct tcp_fragment *fragment) {

	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	// 1 eth header
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pktdata;
	eth->s_addr = d_addr;
	eth->d_addr = s_addr;
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 ip header
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pktdata + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_TCP;
	ip->src_addr = dstip;
	ip->dst_addr = srcip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 tcp header 

	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(pktdata + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp->src_port = fragment->srcport;
	tcp->dst_port = fragment->dstport;
	tcp->sent_seq = htonl(fragment->seq);
	tcp->recv_ack = htonl(fragment->ack);

	tcp->data_off = fragment->offset;
	tcp->rx_win = fragment->windows;
	tcp->tcp_urp = fragment->tcp_urp;
	tcp->tcp_flags = fragment->tcp_flags;

	if (fragment->data != NULL) {
		uint8_t *payload = (uint8_t*)(tcp+1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}

	tcp->cksum = 0;
	tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

	return mbuf;
}

static int tcp_out(struct rte_mempool *mbuf_pool,struct rte_ether_addr s_addr,struct rte_ether_addr d_addr){
	struct tcp_table *table = tcpInstance();
	struct tcp_stream *stream;
	for (stream = table->tcb_set; stream !=NULL;stream = stream->next){
		struct tcp_fragment *fragment = NULL;
		int num_send = rte_ring_mc_dequeue(stream->sendbuffer, (void**)&fragment);
		if (num_send<0) continue;
		struct rte_mbuf *tcpbuf = tcp_pkt(mbuf_pool, stream->srcip, stream->dstip,s_addr,d_addr, fragment);
		struct inout_ring *ring = ringInstance();
		rte_ring_mp_enqueue_burst(ring->out, (void **)&tcpbuf, 1, NULL);
		if (fragment->data != NULL)
			rte_free(fragment->data);
		rte_free(fragment);
	} 
	return 0;
}


#endif


#if ENABLE_KNI
/* Callback for request of configuring network interface up/down */
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
	int ret = 0;
	
	if (!rte_eth_dev_is_valid_port(port_id)) {
		
		return -EINVAL;
	}

	if (if_up != 0) { /* Configure network interface up */
		
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
		
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);
	if (ret < 0)
		printf("Failed to start port : %d\n", port_id);
	
	return ret;
}

static void print_ethaddr(const char *name, struct rte_ether_addr *mac_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
	printf("\t%s %s\n", name, buf);
}

static struct rte_kni * kni_alloc(struct rte_mempool *mbuf_pool){

	struct rte_kni *kni = NULL;
	struct rte_kni_conf conf;

	/* Clear conf at first */
	memset(&conf, 0, sizeof(conf));
	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", DpdkPortId);
	conf.group_id = DpdkPortId;
	conf.mbuf_size = MAX_PACKET_SZ;
	rte_eth_macaddr_get(DpdkPortId, (struct rte_ether_addr *)conf.mac_addr);
	rte_eth_dev_get_mtu(DpdkPortId, &conf.mtu);
	print_ethaddr("Address:", (struct rte_ether_addr *)conf.mac_addr);

	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));

	ops.port_id = DpdkPortId;
	ops.config_network_if = kni_config_network_interface;

	kni = rte_kni_alloc(mbuf_pool, &conf, &ops);
	if (!kni)
		rte_exit(EXIT_FAILURE, "Fail to create kni for port: %d\n", DpdkPortId);

	return kni;
}
#endif


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
	rte_eth_dev_info_get(DpdkPortId, &dev_info); 
	printf("Dev info\n driver_name : %s\n if_index: %d\n mtu: %d %d\n Queue: %d %d\n", dev_info.driver_name,dev_info.if_index,dev_info.max_mtu,dev_info.min_mtu,dev_info.nb_rx_queues,dev_info.nb_tx_queues);


	// Setuo rx & tx queue for NIC
	const int num_rx_queues = 1;
	const int num_tx_queues = 1;

	//NIC configuration struct
	struct rte_eth_conf port_conf = port_conf_default;
	//Configure the NIC with queue parameters
	rte_eth_dev_configure(DpdkPortId, num_rx_queues, num_tx_queues, &port_conf);


	//1024 is uint16_t nb_rx_desc , it stands for the length of the rx queue. 1024 packets
	if (rte_eth_rx_queue_setup(DpdkPortId, 0 , 1024, 
		//When receiving data from interface, the data will be stored at this mbuf_pool
		rte_eth_dev_socket_id(DpdkPortId),NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}

	//set up configuration for tx
	struct rte_eth_txconf tx_conf = dev_info.default_txconf;
	//set up tx offload which is size of data transfer
	tx_conf.offloads = port_conf_default.rxmode.offloads;
	printf("Offload: %d\n", (int)tx_conf.offloads);
	
	if (rte_eth_tx_queue_setup(DpdkPortId, 0 , 1024, rte_eth_dev_socket_id(DpdkPortId), &tx_conf) < 0) {
		//TX queue
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}

	
	//Start the NIC
	if ( rte_eth_dev_start(DpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}
}



static int pkt_process(void *arg){
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ringInstance();
	while (1){
		struct rte_mbuf *pkt_mbufs[BURST_SIZE];
		unsigned num_in = rte_ring_mc_dequeue_burst(ring->in, (void**)pkt_mbufs,BURST_SIZE,NULL);
		unsigned i = 0;
		for (i = 0; i< num_in; i++){
			
			//ethernet
			struct rte_ether_hdr *eth_header = rte_pktmbuf_mtod(pkt_mbufs[i],struct rte_ether_hdr*);
			if (eth_header->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
				continue;
			}

			//IPv4 & TCP
			struct rte_ipv4_hdr *ip_header = rte_pktmbuf_mtod_offset(pkt_mbufs[i],struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
			if (ip_header->next_proto_id == IPPROTO_TCP){
				tcp_process(pkt_mbufs[i]);
				tcp_out(mbuf_pool,eth_header->s_addr,eth_header->d_addr);
			}
			else{
				rte_kni_tx_burst(global_kni,pkt_mbufs,num_in);
				printf("Other protocol to KNI\n");
				rte_kni_handle_request(global_kni);
				rte_pktmbuf_free(pkt_mbufs[i]);
			}
		}	
	}
	return 0;
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

	#if ENABLE_KNI
	//Initiate the KNI
	if (rte_kni_init(RTE_MAX_ETHPORTS) <0) rte_exit(EXIT_FAILURE, "Could not initiate KNI\n");
	rte_eth_promiscuous_enable(DpdkPortId);
	global_kni = kni_alloc(mbuf_pool);
	#endif

	struct inout_ring *ring = ringInstance();
	if (ring == NULL) {
		rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
	}

	if (ring->in == NULL) {
		ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (ring->out == NULL) {
		ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}

	unsigned lcore_id = rte_lcore_id();
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);
	while (1) {
		
		#if ENABLE_KNI
		//receive data from Kernel
		struct rte_mbuf *pkt_kni_mbufs[BURST_SIZE];
		unsigned num = rte_kni_rx_burst(global_kni, pkt_kni_mbufs, BURST_SIZE);
		
		if (num > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from Kernel\n");
			continue;
		}
		else if (num > 0){
			rte_eth_tx_burst(DpdkPortId,0,pkt_kni_mbufs,num);
			unsigned i = 0;
			for (i = 0 ; i < num; i++){
				rte_pktmbuf_free(pkt_kni_mbufs[i]);
			}
		}
		#endif


		struct rte_mbuf *recv_mbufs[BURST_SIZE];
		// receive data from interface / queue / memory buffer / receive size
		//mbufs -> mbuf_pool in setup rx 
		unsigned num_recvd = rte_eth_rx_burst(DpdkPortId, 0, recv_mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
		else if (num_recvd > 0){
			rte_ring_sp_enqueue_burst(ring->in,(void**)recv_mbufs,num_recvd,NULL);
			
		}
		
		struct rte_mbuf *send_mbufs[BURST_SIZE];
		// send data
		unsigned num_send = rte_ring_sc_dequeue_burst(ring->out,(void**)send_mbufs,BURST_SIZE,NULL);
		if (num_send > 0){
			rte_eth_tx_burst(DpdkPortId,0,send_mbufs,num_send);
			unsigned i = 0;
			for (i = 0 ; i < num_send; i++){
				rte_pktmbuf_free(send_mbufs[i]);
			}
		}
	}
}
