#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <unistd.h>

#include <stdio.h>
#include <arpa/inet.h>


#ifdef RTE_LIB_PDUMP
#include <rte_pdump.h>
#endif


#define NUM_MBUFS (65536-1)
#define RING_SIZE       65536
#define BURST_SIZE      1024
#define BATCH_NUM       1
#define RX_QUEUE_SIZE 1024
#define TX_QUEUE_SIZE 1024
#define NUM_RX_QUEUES 7
#define NUM_TX_QUEUES 7

#define ENABLE_LOG 0

const char *A_RECORD = "1.1.1.1";

// setup NIC number
int gDpdkPortId = 0;

struct lcore_config {
    struct rte_mempool *mbuf_pool;
    unsigned queue_id;
};
static struct lcore_config lcore_cfgs[NUM_RX_QUEUES];

struct inout_ring {
        struct rte_ring *in;
        struct rte_ring *out;
};

static struct inout_ring *rInst = NULL;

static struct inout_ring *ringInstance(void) {

        if (rInst == NULL) {
                rInst = rte_malloc("r", sizeof(struct inout_ring), 0);
                memset(rInst, 0, sizeof(struct inout_ring));
        }
        return rInst;
}

static const struct rte_eth_conf port_conf_default = {
        .rxmode = {
                .max_lro_pkt_size = RTE_ETHER_MAX_JUMBO_FRAME_LEN,
                .mq_mode =RTE_ETH_MQ_RX_RSS,
        },
        .txmode = {
                .offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
        }
};

static void init_port(struct lcore_config *lcore_cfgs) {

        // check if NIC has been bound with DPDK
        uint16_t nb_sys_ports= rte_eth_dev_count_avail(); 
        if (nb_sys_ports == 0) {
                rte_exit(EXIT_FAILURE, "No Supported eth found\n");
        }

        //NIC info struct
        struct rte_eth_dev_info dev_info;

        // Get raw NIC info via a function provided by DPDK
        int t = rte_eth_dev_info_get(gDpdkPortId, &dev_info); 
        printf("Dev info\n driver_name : %s\n if_index: %d\n mtu: %d %d\n Queue: %d %d\n", dev_info.driver_name,dev_info.if_index,dev_info.max_mtu,dev_info.min_mtu,dev_info.nb_rx_queues,dev_info.nb_tx_queues);

        //NIC configuration struct
        struct rte_eth_conf port_conf = port_conf_default;
        //Configure the NIC with queue parameters
        rte_eth_dev_configure(gDpdkPortId, NUM_RX_QUEUES, NUM_TX_QUEUES, &port_conf);


        //1024 is uint16_t nb_rx_desc , it stands for the length of the rx queue. 1024 packets
        for (int i = 0; i<NUM_RX_QUEUES; i++){
                if (rte_eth_rx_queue_setup(gDpdkPortId, i, RX_QUEUE_SIZE, rte_eth_dev_socket_id(gDpdkPortId), NULL, lcore_cfgs[i].mbuf_pool) < 0) {
                        rte_exit(EXIT_FAILURE, "Failed to setup RX queue %d\n", 0);
                }
                //rte_eth_dev_rx_queue_start(gDpdkPortId, i);
                printf("RX Queue: %d, nb used %d\n",i,rte_eth_rx_queue_count(gDpdkPortId, i));
        }

        //set up configuration for tx
        struct rte_eth_txconf tx_conf = dev_info.default_txconf;
        //set up tx offload which is size of data transfer
        tx_conf.offloads = port_conf_default.rxmode.offloads;
        printf("Offload: %d\n", (int)tx_conf.offloads);

        for (int i = 0; i<NUM_TX_QUEUES; i++){
                if (rte_eth_tx_queue_setup(gDpdkPortId, i, TX_QUEUE_SIZE, rte_eth_dev_socket_id(gDpdkPortId), &tx_conf) < 0) {
                        rte_exit(EXIT_FAILURE, "Failed to setup TX queue %d\n", 0);
                }
                //rte_eth_dev_tx_queue_start(gDpdkPortId, i);
                printf("TX Queue: %d, nb used %d\n",i,rte_eth_tx_queue_count(gDpdkPortId, i));
        }
        

        //Start the NIC
        if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
                rte_exit(EXIT_FAILURE, "Could not start\n");
        }

        // rte_eth_dev_rx_queue_start(gDpdkPortId, 0);
        //         printf("RX Queue: 0, nb used %d\n",rte_eth_rx_queue_count(gDpdkPortId, 0));
        // rte_eth_dev_tx_queue_start(gDpdkPortId, 0);
        //         printf("TX Queue: 0, nb used %d\n",rte_eth_tx_queue_count(gDpdkPortId, 0));

}

static void pkt_process(struct rte_mempool *mbuf_pool,struct rte_mbuf *mbufs, unsigned queue){

        uint8_t srcmac[RTE_ETHER_ADDR_LEN];
        uint8_t dstmac[RTE_ETHER_ADDR_LEN];
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port; 
        uint16_t transaction_id;
     
        struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs, struct rte_ether_hdr*);
        if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                return;
        }  

 /*
        char ebuf_src[RTE_ETHER_ADDR_FMT_SIZE];
        char ebuf_dst[RTE_ETHER_ADDR_FMT_SIZE];
        rte_ether_format_addr(ebuf_src,sizeof(ebuf_src),&ehdr->src_addr);
        rte_ether_format_addr(ebuf_dst,sizeof(ebuf_dst),&ehdr->dst_addr);
        rte_pktmbuf_dump(stdout, mbufs, 100);
        if (strcmp(ebuf_src,ebuf_dst)==0){
                //printf("Free count: %d\n",rte_ring_free_count(ring->in));
                //rte_pktmbuf_dump(stdout, mbufs, 100);
                printf("MAC ERROR From RX queue %d\n",queue);
                //rte_exit(EXIT_FAILURE, "RX Dst MAC error\n");
        }
        //printf("%s, %s\n",ebuf_src,ebuf_dst);
 */

        struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs, struct rte_ipv4_hdr *, 
        sizeof(struct rte_ether_hdr));
        if (iphdr->src_addr == iphdr->dst_addr){
                printf("RX Same address\n");
                return;
        }

        if (iphdr->next_proto_id == IPPROTO_UDP && (iphdr->time_to_live-1) > 252){
                /*Get UDP header.
                Two ways:
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)((unsigned char *)iphdr + sizeof(struct rte_ipv4_hdr));
                */
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
                // Length in UDP header means all payload + UDP header
                uint16_t length = ntohs(udphdr->dgram_len);
                //*((char*)udphdr + length) = '\0';

                //printf("Data: %s\n", (unsigned char *)udphdr +1);
                unsigned char domain[128], *dns = domain;
                unsigned char *pp = rte_pktmbuf_mtod_offset(mbufs,unsigned char *,42);
                //pp += 8; /* Move to DNS  */
                transaction_id = ntohs(*((unsigned short*)pp));
                pp += 4; /* Move to Question in DNS Query */
                int question = ntohs(*((unsigned short*)pp));
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
                const unsigned dns_len = 34 + strlen((char *)domain);
        //printf("Length of domain %ld\n", strlen((char *)domain));


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



        //This is total length
        const unsigned total_len = dns_len + 8 + 20 + 14;

        //Allocate a new mbuf from a mempool.
        struct rte_mbuf *new_mbuf = rte_pktmbuf_alloc(mbuf_pool);
        //memset(new_mbuf->buf_addr + new_mbuf->data_off, 0, total_len);
        if (!new_mbuf){
                //memset(new_mbuf->buf_addr + new_mbuf->data_off, 0, total_len);
                rte_exit(EXIT_FAILURE, "Not able to allocate mbuf\n");
        }
        new_mbuf->data_len = total_len;
        new_mbuf->pkt_len = total_len;
        //uint8_t *pkt = rte_pktmbuf_mtod(new_mbuf, uint8_t*);
        uint8_t *pkt = rte_pktmbuf_prepend(new_mbuf, total_len); //it works
        //memset(pkt, 0, total_len);
        
        //Layer2 build
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
        rte_memcpy(eth->src_addr.addr_bytes,ehdr->dst_addr.addr_bytes,RTE_ETHER_ADDR_LEN);
        rte_memcpy(eth->dst_addr.addr_bytes,ehdr->src_addr.addr_bytes,RTE_ETHER_ADDR_LEN);
        eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
        if (eth->src_addr.addr_bytes == eth->dst_addr.addr_bytes){
                printf("TX MAC Same address\n");
                rte_pktmbuf_free(new_mbuf);
                return;
        }

/* 
        char tx_ebuf_src[RTE_ETHER_ADDR_FMT_SIZE];
        char tx_ebuf_dst[RTE_ETHER_ADDR_FMT_SIZE];
        rte_ether_format_addr(tx_ebuf_src,sizeof(ebuf_src),&eth->src_addr);
        rte_ether_format_addr(tx_ebuf_dst,sizeof(ebuf_dst),&eth->dst_addr);
        if (strcmp(tx_ebuf_src,tx_ebuf_dst)==0){
                //printf("Free count: %d\n",rte_ring_free_count(ring->in));
                printf("Origin %s, %s\n",ebuf_src,ebuf_dst);
                printf("Reply %s, %s\n",tx_ebuf_src,tx_ebuf_dst);
                rte_pktmbuf_dump(stdout, new_mbuf, 100);
                printf("MAC ERROR From TX queue %d\n",queue);
                rte_exit(EXIT_FAILURE, "TX Dst MAC error\n");
        }
*/
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

        // printf("Src: %d, ", ip->src_addr);
        // printf("Dst: %d\n", ip->dst_addr);
        rte_memcpy(&ip->src_addr, &iphdr->dst_addr, sizeof(uint32_t));
        rte_memcpy(&ip->dst_addr, &iphdr->src_addr, sizeof(uint32_t));
        //ip->src_addr = iphdr->dst_addr;
        //ip->dst_addr = iphdr->src_addr;
        if (ip->src_addr == ip->dst_addr){
                printf("TX Same address\n");
                rte_pktmbuf_free(new_mbuf);
                return;
        }
        //Initate checksum to 0 to prevent on premise value of checksum in the calculation.
        ip->hdr_checksum = 0;

        //Layer4 build
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(pkt+ sizeof(struct  rte_ether_hdr) + sizeof(struct  rte_ipv4_hdr));
        rte_memcpy(&udp->src_port, &udphdr->dst_port, sizeof(uint16_t));
        rte_memcpy(&udp->dst_port, &udphdr->src_port, sizeof(uint16_t));
        //udp->src_port = udphdr->dst_port;
        //udp->dst_port = udphdr->src_port;
        udp->dgram_len = htons(dns_len+8);
        udp->dgram_cksum = 0;

        //DNS build
        unsigned char *presend = rte_pktmbuf_mtod_offset(new_mbuf,unsigned char *,42);
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
        struct in_addr addr;
        inet_aton(A_RECORD,&addr);
        //printf("IP: %s, length is %ld\n",A_RECORD, strlen(A_RECORD));
        rte_memcpy(presend,&addr.s_addr,INET_ADDRSTRLEN); // RDATA

        udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip,udp);
        ip->hdr_checksum = rte_ipv4_cksum(ip);
        //printf("Constructing completed!\n");
        //rte_ring_mp_enqueue_burst(ring->out,(void**)&mbuf,BATCH_NUM,NULL);
        int sent = rte_eth_tx_burst(gDpdkPortId,queue,&new_mbuf,BATCH_NUM);
        
        //printf("%d packets has been sent\n", num);
        rte_pktmbuf_free(new_mbuf);

        //Free a packet mbuf back into its original mempool.
        //rte_pktmbuf_free(mbufs);
        //int t = sleep(1);

#if ENABLE_LOG
        rte_eth_macaddr_get(gDpdkPortId,(struct rte_ether_addr *)srcmac);
        //rte_memcpy(srcmac,ehdr->d_addr.addr_bytes,RTE_ETHER_ADDR_LEN);
        rte_memcpy(dstmac,ehdr->src_addr.addr_bytes,RTE_ETHER_ADDR_LEN);
        rte_memcpy(&src_ip,&iphdr->dst_addr,sizeof(uint32_t));
        rte_memcpy(&dst_ip,&iphdr->src_addr,sizeof(uint32_t));
        rte_memcpy(&src_port,&udphdr->dst_port,sizeof(uint32_t));
        rte_memcpy(&dst_port,&udphdr->src_port,sizeof(uint32_t));
        //src_port = ntohs(udphdr->dst_port);
        //dst_port = ntohs(udphdr->src_port);
        printf("SrcPort: %d\n",ntohs(src_port));
        printf("DstPort: %d\n",ntohs(dst_port));
        printf("Question: %d\n",question);
        printf("Domain: %s, length is %ld\n",domain, strlen((char *)domain)+2);
        printf("-------------------------------\n");
        printf("Transaction_id: %d\n",transaction_id);
        printf("Length of UDP: %d\n", length);
        struct in_addr addr;
        addr.s_addr = iphdr->src_addr;
        printf("Src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));
        addr.s_addr = iphdr->dst_addr;
        printf("Dst: %s:%d\n", inet_ntoa(addr), ntohs(udphdr->dst_port));
#endif

        }

}

static int loop(void *arg){
        struct lcore_config *cfg = arg;
        unsigned lcore_id = cfg->queue_id;
        struct rte_mempool *mbuf_pool = cfg->mbuf_pool;
        printf("CPU core(Queue): %d %d. Process thread. Mem pool address %p\n",lcore_id,rte_lcore_id(),(void *)mbuf_pool);
        //struct inout_ring *ring = ringInstance();

        while(1){
                struct rte_mbuf *mbufs[BURST_SIZE];
                unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, lcore_id, mbufs, BURST_SIZE);
                if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
                for (int i = 0; i< num_recvd; i++){
                        pkt_process(mbuf_pool,mbufs[i],lcore_id);
                        rte_pktmbuf_free(mbufs[i]);
                }
        }
        return 0;

}

/*
static int pkt_out(void *arg){

        
        printf("CPU core: %d. TX thread\n",rte_lcore_id());
        struct inout_ring *ring = ringInstance();
        struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;

        while (1){
                struct rte_mbuf *pkt_mbufs[BURST_SIZE];
                unsigned num = rte_ring_sc_dequeue_burst(ring->out, (void **)pkt_mbufs,BURST_SIZE,NULL);

                if (num == 0){
                        continue;
                }
                rte_eth_tx_burst(gDpdkPortId,0,pkt_mbufs,num);
                rte_pktmbuf_free_bulk(pkt_mbufs,num);
                
        }
        return 0;
}
*/

int main(int argc, char *argv[]) {



        if (rte_eal_init(argc, argv) < 0) 
                rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

        #ifdef RTE_LIB_PDUMP
                /* initialize packet capture framework */
                rte_pdump_init();
        #endif

        unsigned lcore_id = rte_lcore_id();
        struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mp0", NUM_MBUFS,
                RTE_MEMPOOL_CACHE_MAX_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (mbuf_pool == NULL) {
                rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
        }
        struct lcore_config *cfg0 = &lcore_cfgs[lcore_id];
        cfg0->mbuf_pool = mbuf_pool;
        cfg0->queue_id = lcore_id;
        printf("CPU core(Queue): %d. main thread, Mem pool address %p\n",lcore_id,(void *)mbuf_pool);

        for (int i =1; i < NUM_RX_QUEUES; i++){
                lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
                struct lcore_config *cfg = &lcore_cfgs[lcore_id];

                char pool_name[32];
                snprintf(pool_name, sizeof(pool_name), "mp%d", i);

                struct rte_mempool *mp = rte_pktmbuf_pool_create(pool_name, NUM_MBUFS,
                        RTE_MEMPOOL_CACHE_MAX_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
                if (mp == NULL) {
                        rte_exit(EXIT_FAILURE, "Could not create mbuf pool: %s\n", pool_name);
                }
                cfg->mbuf_pool = mp;
                cfg->queue_id = lcore_id;
                
        }

        init_port(lcore_cfgs);



        // struct inout_ring *ring = ringInstance();
        // if (ring == NULL) {
        //         rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
        // }

        // if (ring->in == NULL) {
        //         ring->in = rte_ring_create("in", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_MC_HTS_DEQ);
        // }
        // if (ring->out == NULL) {
        //         ring->out = rte_ring_create("out", RING_SIZE, rte_socket_id(), RING_F_MP_HTS_ENQ | RING_F_SC_DEQ);
        // }
        // printf("Ring Capacity: In %d , Out %d\n",ring->in->capacity,ring->out->capacity);
        for (int i =1; i < NUM_RX_QUEUES; i++){
                rte_eal_remote_launch(loop, &lcore_cfgs[i], i); 
        }



        while (1) {

                struct rte_mbuf *mbufs[BURST_SIZE];
                unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
                if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
                
                for(int i = 0 ; i < num_recvd; i++) {
                        //rte_pktmbuf_dump(stdout, mbufs[i], 100);
                        //rte_ring_sp_enqueue_burst(ring->in,(void**)mbufs,num_recvd,NULL);
                        pkt_process(mbuf_pool,mbufs[i],0);
                        rte_pktmbuf_free(mbufs[i]);
                }  
                
                //rte_pktmbuf_free_bulk(mbufs,num_recvd);           
                
        }

        #ifdef RTE_LIB_PDUMP
                /* uninitialize packet capture framework */
                rte_pdump_uninit();
        #endif
}
