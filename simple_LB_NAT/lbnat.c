#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_malloc.h>
#include <rte_kni.h>
#include <rte_log.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>

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
#define TARGET_NUM 2
#define HIGH_PORT 65535
#define LOW_PORT 1024
#define MAX_ENTRIES 65535
#define HASH_FUNC rte_hash_crc



#define ENABLE_KNI 0
#define ENABLE_TCP 0
#define ENABLE_LBNAT 1

#define MAX_PACKET_SZ           2048
/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

// setup NIC number
int DpdkPortId = 0;
int fd = 0;
struct rte_kni *global_kni = NULL;
const char *target_ip[TARGET_NUM] = {"10.0.0.156","10.0.0.139"};
const char *target_mac[TARGET_NUM] = {"06:b8:6a:5f:27:30","06:cf:dc:28:2c:a6"};
const char *eip = "10.0.0.67";
int ind = 0;
uint16_t eport = LOW_PORT; //to allocate external source port

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
		printf("11111111111 and %d\n",ret);
		ret = rte_eth_dev_start(port_id);
		printf("22222222222 and %d\n",ret);
		//rte_kni_update_link(global_kni,1);
		
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);
	if (ret < 0)
		printf("Failed to start port : %d\n", port_id);
	
	return ret;
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

#if ENABLE_LBNAT

struct arp_entry {
	uint32_t ip;
	uint8_t macaddr[RTE_ETHER_ADDR_LEN];

	struct arp_entry *next;
	struct arp_entry *prev;
	
};

struct arp_table {
	struct arp_entry *entries;
	int count;
};

static struct  arp_table *arpt = NULL;

static struct  arp_table *arpInstance(void) {
	if (arpt == NULL) {
		arpt = rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		}
		memset(arpt, 0, sizeof(struct  arp_table));
	}
	return arpt;
}

static uint8_t *get_mac(uint32_t dip) {

	struct arp_entry *iter;
	struct arp_table *table = arpInstance();
	for (iter = table->entries;iter != NULL;iter = iter->next) {
		if (dip == iter->ip) {
			return iter->macaddr;
		}
	}
	return NULL;
}

struct connection_out {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
	uint8_t protocol;
};

struct connection_in {
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
	uint8_t protocol;
};

struct loadbalance {
	uint32_t targetip;
	uint8_t targetmac[RTE_ETHER_ADDR_LEN];
};

struct connection {
	struct connection_out out[MAX_ENTRIES];
	struct connection_in in[MAX_ENTRIES];
	struct loadbalance lb[MAX_ENTRIES];
	struct rte_hash *hash_table_out;
	struct rte_hash *hash_table_in;
	struct rte_hash *hash_table_lb;
	uint16_t size;

};

static struct connection *conInst = NULL;
static struct connection *conInstance(void) {
	if (conInst == NULL) {
		
		conInst = rte_malloc("connection information", sizeof(struct connection), 0);
		memset(conInst, 0, sizeof(struct connection));
		memset(conInst->out,0,sizeof(struct connection_out));
		memset(conInst->in,0,sizeof(struct connection_in));
		memset(conInst->lb,0,sizeof(struct loadbalance));
		
		conInst->size = 0;
		struct rte_hash_parameters hash_params_out = {
			.name = "con_out_table",
			.entries = MAX_ENTRIES,
			.key_len = sizeof(struct connection_out),
			.hash_func = HASH_FUNC,
			.hash_func_init_val = 0,
		};

		struct rte_hash_parameters hash_params_in = {
			.name = "con_in_table",
			.entries = MAX_ENTRIES,
			.key_len = sizeof(struct connection_in),
			.hash_func = HASH_FUNC,
			.hash_func_init_val = 0,
		};
		struct rte_hash_parameters hash_params_lb = {
			.name = "con_lb_table",
			.entries = MAX_ENTRIES,
			.key_len = sizeof(struct connection_out),
			.hash_func = HASH_FUNC,
			.hash_func_init_val = 0,
		};

		conInst->hash_table_out = rte_hash_create(&hash_params_out);
		conInst->hash_table_in = rte_hash_create(&hash_params_in);
		conInst->hash_table_lb = rte_hash_create(&hash_params_lb);
		if (conInst->hash_table_out == NULL || conInst->hash_table_in == NULL || conInst->hash_table_lb == NULL) {
			printf("Failed to create hash table\n");
			return NULL;
   		}
	}

	return conInst;
}

static int process_tcp(struct rte_mbuf *mbuf_pool){
	struct rte_ether_hdr *eth_header = rte_pktmbuf_mtod(mbuf_pool,struct rte_ether_hdr*);
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

	struct connection *con = conInstance();
	int ret_out, ret_in,ret_lb;
	struct in_addr saddr;
	
	//Forward 172.31.27.54 10038 -> 10.0.0.67 80  => 10.0.0.67 14589 -> 10.0.0.156 80
	//Reverse 10.0.0.156 80 -> 10.0.0.67 14589  => 10.0.0.67 80 -> 172.31.27.54 10038


		//Forward = con_out
		con->out[ind].src_ip = ip_header->src_addr;
		con->out[ind].dst_ip = ip_header->dst_addr;
		con->out[ind].src_port = ntohs(tcp_header->src_port);
		con->out[ind].dst_port = ntohs(tcp_header->dst_port);
		con->out[ind].protocol = ip_header->next_proto_id;

		//Reverse = con_in
		con->in[ind].dst_ip = ip_header->src_addr;
		con->in[ind].src_port = ntohs(tcp_header->dst_port);
		con->in[ind].dst_port = ntohs(tcp_header->src_port);
		con->in[ind].protocol = ip_header->next_proto_id;

	uint8_t *tempmac = get_mac(ip_header->src_addr);
	if (tempmac == NULL){
		struct arp_table *table = arpInstance();	
		struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
		entry->ip = ip_header->src_addr;
		saddr.s_addr = ip_header->src_addr;
		rte_memcpy(entry->macaddr,eth_header->s_addr.addr_bytes,RTE_ETHER_ADDR_LEN);
		entry->prev = NULL;		
		entry->next = table->entries;			
		if (table->entries != NULL) table->entries->prev = entry;
		table->entries = entry;
	}

	struct connection_out *out_temp = NULL;
	struct connection_in *in_temp = NULL;
	struct loadbalance *lb_temp = NULL;

	ret_out = rte_hash_lookup_data(con->hash_table_out, &con->out[ind], (void **)&in_temp);
	ret_in = rte_hash_lookup_data(con->hash_table_in, &con->in[ind], (void **)&out_temp);
	printf("out: %d in: %d\n",ret_out,ret_in);

	if(ret_out <0 && ret_in <0){
		//add LB information
		inet_aton(target_ip[eport%2],&saddr);
		con->lb[ind].targetip = saddr.s_addr;
		ip_header->dst_addr = saddr.s_addr;
		inet_aton(eip,&saddr);
		ip_header->src_addr = saddr.s_addr;
		rte_eth_macaddr_get(DpdkPortId, &eth_header->s_addr);
		rte_ether_unformat_addr(target_mac[eport%2],&eth_header->d_addr);
		rte_memcpy(&con->lb[ind].targetmac,&eth_header->d_addr.addr_bytes,RTE_ETHER_ADDR_LEN);

		//New flow from client
		tcp_header->src_port = htons(eport);
		con->in[ind].dst_ip = ip_header->dst_addr;
		con->in[ind].src_port = eport;
		con->in[ind].dst_port = ntohs(tcp_header->dst_port);
		
		int ret = rte_hash_add_key_data(con->hash_table_out, &con->out[ind], &con->in[ind]);
		if (ret < 0) printf("Failed to insert out table\n");
		ret = rte_hash_add_key_data(con->hash_table_in, &con->in[ind], &con->out[ind]);
		if (ret < 0) printf("Failed to insert in table\n");
		ret = rte_hash_add_key_data(con->hash_table_lb, &con->out[ind], &con->lb[ind]);
		if (ret < 0) printf("Failed to insert lb table\n");
		ret = rte_hash_count(con->hash_table_out);
		printf("table size: %d %d %d \n",ret, rte_hash_count(con->hash_table_in), rte_hash_count(con->hash_table_lb));
				
		ip_header->hdr_checksum = 0;
		ip_header->hdr_checksum=rte_ipv4_cksum(ip_header);
		tcp_header->cksum=0;
		tcp_header->cksum = rte_ipv4_udptcp_cksum(ip_header,tcp_header);
		struct inout_ring *ring = ringInstance();
		rte_ring_mp_enqueue_burst(ring->out, (void **)&mbuf_pool, 1, NULL);
		ind++;
		eport++;

	}
	else if(ret_out >=0 && ret_in < 0){
		//Subsequent packets from client
		printf("Subsequent packets from client\n");
		ret_lb = rte_hash_lookup_data(con->hash_table_lb,&con->out[ind], (void **)&lb_temp);
		if (ret_lb < 0) printf("No LB information\n"); 
		//tempmac = get_mac(in_temp->dst_ip);
		//if (tempmac == NULL) printf("No mac for client\n");
		rte_memcpy(&eth_header->d_addr.addr_bytes,&lb_temp->targetmac,RTE_ETHER_ADDR_LEN);
		rte_eth_macaddr_get(DpdkPortId, &eth_header->s_addr);
		inet_aton(eip,&saddr);
		ip_header->src_addr = saddr.s_addr;
		ip_header->dst_addr = in_temp->dst_ip;
		tcp_header->src_port = htons(in_temp->src_port);
		tcp_header->dst_port = htons(in_temp->dst_port);

		ip_header->hdr_checksum = 0;
		ip_header->hdr_checksum=rte_ipv4_cksum(ip_header);
		tcp_header->cksum=0;
		tcp_header->cksum = rte_ipv4_udptcp_cksum(ip_header,tcp_header);
		struct inout_ring *ring = ringInstance();
		rte_ring_mp_enqueue_burst(ring->out, (void **)&mbuf_pool, 1, NULL);

	}
	else if (ret_out <0 && ret_in >=0){
		//Subsequent packets from target
		//Reverse 10.0.0.156 80 -> 10.0.0.67 14589  => 10.0.0.67 80 -> 172.31.27.54 10038

		printf("Subsequent packets from target\n");
		uint8_t *tempmac = get_mac(out_temp->src_ip);
		if (tempmac == NULL) printf("No mac for client\n");
		rte_memcpy(&eth_header->d_addr.addr_bytes,tempmac,RTE_ETHER_ADDR_LEN);
		rte_eth_macaddr_get(DpdkPortId, &eth_header->s_addr);
		ip_header->src_addr = out_temp->dst_ip;
		ip_header->dst_addr = out_temp->src_ip;
		tcp_header->src_port = htons(out_temp->dst_port);
		tcp_header->dst_port = htons(out_temp->src_port);

		
		ip_header->hdr_checksum = 0;
		ip_header->hdr_checksum=rte_ipv4_cksum(ip_header);
		tcp_header->cksum=0;
		tcp_header->cksum = rte_ipv4_udptcp_cksum(ip_header,tcp_header);
		struct inout_ring *ring = ringInstance();
		rte_ring_mp_enqueue_burst(ring->out, (void **)&mbuf_pool, 1, NULL);
		
	}
	return 0;

	




}


static int process_udp(struct rte_mbuf *mbuf_pool){

	struct rte_ipv4_hdr *ip_header = rte_pktmbuf_mtod_offset(mbuf_pool,struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr *udp_header = (struct rte_udp_hdr *)(ip_header+1);
	//struct rte_tcp_hdr *tcp_header = rte_pktmbuf_mtod_offset(mbuf_pool,struct rte_tcp_hdr*, (sizeof(struct rte_ipv4_hdr)+sizeof(struct rte_ether_hdr)));

	uint16_t udpchecksum = udp_header->dgram_cksum;
	udp_header->dgram_cksum = 0;
	uint16_t cksum = rte_ipv4_udptcp_cksum(ip_header,udp_header);
	if (cksum != udpchecksum){
		printf("cksum: %x, tcp checksum %x\n",cksum,udpchecksum);
		rte_pktmbuf_free(mbuf_pool);
		return -1;
	}
	return 0;

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
	struct inout_ring *ring = ringInstance();
    // create hash table
	struct connection *con = conInstance();
	if (con == NULL) 
		rte_exit(EXIT_FAILURE, "connection information init failed\n");



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
				process_tcp(pkt_mbufs[i]);
			}
			else if (ip_header->next_proto_id == IPPROTO_UDP){
				process_udp(pkt_mbufs[i]);
			}
			
			
			
			/* For TCP and KNI function
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
			*/
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
			printf("number of J = %d\n",j);
			j++;
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
