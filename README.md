seq_server
==========

A basic server build with scapy. seq_server will serve different HTTP responses depending on the TCP sequence number used in the SYN packet issued by the client initiating the TCP handshake.
This code is a proof of concept meant only as an example to show how overhead protocol fields can be repurposed.
An application could just as easily stuff encrypted data into the TCP sequence number, TCP reserved bits, or UDP checksum.


Usage
-----

	python seq_server.py (to start start server)
	python seq_client.py (to issue proper client request)
	python seq_client_nadda.py (to issue improper client request)


Limitations
-----------

- This code is not reliable and is meant only as a PoC
- Middleboxes, such as NAT devices, can and will rewrite TCP sequence numbers rendering this code useless
- seq_server and seq_client must have a shared secret in the sequence generation algorithm
- HTTP server responses are not fully implemented
- Client code often sends multiple packets during testing, not sure why
