# Tftp-server-UDP-
The TFTP allows a client to upload or download files to a server. 
Use UDP sockets.
We’ll be transferring files.
Use the octet mode of transfer. (netascii is simply ascii for us)
The transfer identifiers (TID's) are simply the UDP port number, the TID notation is used across the RFC
Ignore figure 3-1 and its content, it talks about a very high overview that we’re not concerned with now.
Regarding the block numbers;
When a client sends a write request, the server responds with a packet with block number 0 to indicate that a client can proceed their upload
When a client sends a read request, the first block sent from the server will have a block number of 1
Example
Client: RRQ, SERVER: DATA-BLOCK#1
Client: WRQ, SERVER: ACK-BLOCK#0
The server always runs on port 69
If you’re implementing a server and you receive a packet with a wrong port, ignore it.
8-bit format means “byte”
