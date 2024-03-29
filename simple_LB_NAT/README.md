# Simple Load Balancer with NAT function

Code is running on AWS EC2.
##### Topo
Client 172.31.27.54 -- Transit Gateway -- DPDK 10.0.0.67 -- Servers(10.0.0.156 & 10.0.0.139)

##### Feature
The code doesn't include ARP handling because EC2 network handles it.  
Load Balancing algorithm is Round Robin.  
DPDK receive client's packets and change source IP and destination IP into DPDK IP and server IP respectively.  
DPDK hash table is used to store NAT & LB information.
For example:  
>//Forward 172.31.27.54 10038 -> 10.0.0.67 80  => 10.0.0.67 14589 -> 10.0.0.156 80  
//Reverse 10.0.0.156 80 -> 10.0.0.67 14589  => 10.0.0.67 80 -> 172.31.27.54 10038

It only can handle TCP traffic as of now.  
Working on connection destruction and UDP traffic.

#### How to start
1. Setup environment variable    
2. Copy the directory to examples/    
3. make    
4. ./build/lbnat   
5. Run curl on client to DPDK interface IP address.    

```
[root@ip-172-31-27-54 ec2-user]# curl 10.0.0.67 
Hello from Nginx 10.0.0.156 !
[root@ip-172-31-27-54 ec2-user]# curl 10.0.0.67 
Hello from Apache 10.0.0.139 !
[root@ip-172-31-27-54 ec2-user]# curl 10.0.0.67 
Hello from Nginx 10.0.0.156 !
[root@ip-172-31-27-54 ec2-user]# curl 10.0.0.67 
Hello from Apache 10.0.0.139 !
```
