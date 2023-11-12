# Simple TCP Server handles TCP flow

##### Feature
The code doesn't include ARP handling. You may need to implement ARP function by yourself.  
Client initiates connection to DPDK. DPDK accepts connection.  
DPDK will respond same data once client sends data to DPDK.
KNI will handle any other type of traffic like ICMP if you enable the interface.


#### How to start
1. Setup environment variable    
2. Copy the directory to examples/    
3. make    
4. ./build/kni    
5. Run telnet on client to DPDK interface IP address. Then type data and press Enter.  

```
#telnet 192.168.1.11 456
Trying 192.168.1.11...
Connected to 192.168.1.11.
Escape character is '^]'.
Hello!
Hello!
Bye
Bye

telnet> q
Connection closed.                      
```