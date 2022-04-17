# dns spoofing

The code doesn't include ARP handling. You may need to implement ARP function by yourself.
1. Setup environment variable  
2. Copy the directory to examples/  
3. Make  
4. ./build/dns_spoofing  
5. Run "dig domain_name @x.x.x.x" on client. x.x.x.x is DPDK interface IP address.  
6. DNS resolution will work.
