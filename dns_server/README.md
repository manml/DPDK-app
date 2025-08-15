# A High Performance DNS Server

The code doesn't include ARP handling. You may need to implement ARP function by yourself.

It's DPDK based DNS resolver. But all DNS records are hard code.

### How to use

#### Server side(DPDK)
1. Setup environment variable  
2. Copy the directory to examples/  
3. Make  
4. ./build/dns  
```
[root@ip-10-0-0-16 dns]# ./build/dns
EAL: Detected CPU lcores: 8
EAL: Detected NUMA nodes: 1
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'PA'
EAL: VFIO support initialized
ENA_DRIVER: ena_get_metrics_entries(): 0x6 customer metrics are supported
ENA_DRIVER: ena_set_queues_placement_policy(): NOTE: LLQ has been disabled as per user's request. This may lead to a huge performance degradation!
ENA_DRIVER: ena_get_metrics_entries(): 0x6 customer metrics are supported
ENA_DRIVER: ena_set_queues_placement_policy(): NOTE: LLQ has been disabled as per user's request. This may lead to a huge performance degradation!
CPU core(Queue): 0. main thread, Mem pool address 0x1006fde40


Dev info
 driver_name : net_ena
 if_index: 0
 mtu: 9216 128
 Queue: 0 0
RX Queue: 0, nb used -95
RX Queue: 1, nb used -95
RX Queue: 2, nb used -95
RX Queue: 3, nb used -95
RX Queue: 4, nb used -95
RX Queue: 5, nb used -95
RX Queue: 6, nb used -95
Offload: 0
TX Queue: 0, nb used -95
TX Queue: 1, nb used -95
TX Queue: 2, nb used -95
TX Queue: 3, nb used -95
TX Queue: 4, nb used -95
TX Queue: 5, nb used -95
TX Queue: 6, nb used -95
ENA_DRIVER: ena_rss_hash_set(): Setting RSS hash fields is not supported. Using default values: 0xc30
CPU core(Queue): 1 1. Process thread. Mem pool address 0x100ce3500
CPU core(Queue): 2 2. Process thread. Mem pool address 0x10a2e3500
CPU core(Queue): 3 3. Process thread. Mem pool address 0x1138e3500
CPU core(Queue): 4 4. Process thread. Mem pool address 0x11cee3500
CPU core(Queue): 5 5. Process thread. Mem pool address 0x1264e3500
CPU core(Queue): 6 6. Process thread. Mem pool address 0x12fae3500
```


#### Client side
1.Create a domainfile like this
```
[root@ip-10-0-0-125 dns]# cat domainfile 
www.mml.com A
```
2.Run "dnsperf  -s 10.0.0.103 -d domainfile -c 100000 -Q100000 -l100" on client. x.x.x.x is DPDK interface IP address.  

```
[root@ip-10-0-0-125 dns]#  dnsperf  -s 10.0.0.103 -d domainfile -c 100000 -Q100000 -l100
DNS Performance Testing Tool
Version 2.14.0

[Status] Command line: dnsperf -s 10.0.0.103 -d domainfile -c 100000 -Q100000 -l100
[Status] Sending queries (to 10.0.0.103:53)
[Status] Started at: Fri Aug 15 13:11:22 2025
[Status] Stopping after 100.000000 seconds
Warning: requested number of clients (-c 100000) per thread (-T) exceeds built-in maximum 256, adjusting

Warning: received a response with an unexpected (maybe timed out) id: 39786
Warning: received a response with an unexpected (maybe timed out) id: 44334
Warning: received a response with an unexpected (maybe timed out) id: 58052
Warning: received a response with an unexpected (maybe timed out) id: 1695
[Timeout] Query timed out: msg id 39782
[Timeout] Query timed out: msg id 44361
[Timeout] Query timed out: msg id 58127
[Timeout] Query timed out: msg id 1647
[Timeout] Query timed out: msg id 29141
Warning: received a response with an unexpected (maybe timed out) id: 45169
[Timeout] Query timed out: msg id 45188
Warning: received a response with an unexpected (maybe timed out) id: 545
[Timeout] Query timed out: msg id 44037
[Timeout] Query timed out: msg id 466
[Timeout] Query timed out: msg id 38506
Warning: received a response with an unexpected (maybe timed out) id: 27373
Warning: received a response with an unexpected (maybe timed out) id: 53656
[Timeout] Query timed out: msg id 27467
Warning: received a response with an unexpected (maybe timed out) id: 26797
Warning: received a response with an unexpected (maybe timed out) id: 42472
Warning: received a response with an unexpected (maybe timed out) id: 43328
[Timeout] Query timed out: msg id 63619
Warning: received a response with an unexpected (maybe timed out) id: 45229
Warning: received a response with an unexpected (maybe timed out) id: 59588
[Timeout] Query timed out: msg id 53711
[Timeout] Query timed out: msg id 26822
[Timeout] Query timed out: msg id 42561
[Timeout] Query timed out: msg id 43328
[Timeout] Query timed out: msg id 45269
[Timeout] Query timed out: msg id 59588
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         9999800
  Queries completed:    9999783 (100.00%)
  Queries lost:         17 (0.00%)

  Response codes:       NOERROR 9999783 (100.00%)
  Average packet size:  request 29, response 45
  Run time (s):         100.000293
  Queries per second:   99997.537007

  Average Latency (s):  0.000185 (min 0.000037, max 0.030840)
  Latency StdDev (s):   0.000150
```

### Explanation
- Using multi-queue of the interface. In my case, it's 7.  
- Using multi-thread to run packet process function. Each thread is running on 1 vCPU.  
- Each thread handle packets from single queue.  
- RSS is enabled.  

In a word, I use 7 vCPU cores to run 7 threads(includes main thread) to handle packets on 7 queues.  

In my test, there will be few lost on client in heavy benchmark. But after investigation, all packets have been handled in DPDK. So I preferred this is because some restrictions on benchmark application dnsperf.
```
# ./usertools/dpdk-telemetry.py
--> /ethdev/xstats,0
"rx_good_packets": 9999922,
"tx_good_packets": 9999800, << This number match "Queries sent: 9999800" on client
```
