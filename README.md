<h1 align="center"> 
	CPSC 416 - Distributed Systems: Assignment 2
</h1>

<h2 align="center"> 
	University of British Columbia
</h2>



<h3>
	<b>High-Level Protocol Description</b>
</h3>

The aserver and fserver must together implement the protocol described in the first assignment.
The interactions between the client and the aserver and the client and the fserver were described 
in the first assignment. All that remains is to describe the interactions between the aserver and 
fserver (which you will implement as separate go programs).

The aserver and fserver communicate via RPC over TCP. The aserver is the server in this RPC interaction 
and exports a single method to the fserver, ``GetFortuneInfo``, that takes the address of the client and a 
pointer to ``FortuneInfoMessage`` for the result. The fserver computes a new nonce and returns the filled-in 
``FortuneInfoMessage``. The exact declaration of ``GetFortuneInfo`` and the input/output types is:


``    type FortuneServerRPC struct{} ::

    // Message with details for contacting the fortune-server.
    type FortuneInfoMessage struct {
    	FortuneServer string // e.g., "127.0.0.1:1234"
	    FortuneNonce  int64  // e.g., 2016
    }
	func (this *FortuneServerRPC) GetFortuneInfo(clientAddr string,	
	fInfoMsg *FortuneInfoMessage) error { ... } ``


This simple RPC interaction is also illustrated in the following diagram:

<p align="center">
	<img alt="Space-Time Diagram" src="/assign2-servers-proto.jpg">
</p>





<h3>
	<b>Implementation requirements</b>
</h3>

 - Both the fserver and the aserver must support multiple concurrent clients.
 - Your aserver and fserver must follow the RPC specification above (i.e., your aserver must inter-operate with our fserver and vice versa).
 - The aserver nonce and the fserver fortune nonce should be unpredictable (e.g., randomized int64 values).
 - The aserver must use the same hashing code as the released client code.
 - You must use UDP and the message types given out in the first assignment.
 - The servers must implement the following protocol-checks and return an appropriate ErrMessage when they occur:
	- fserver: The client sends a malformed message.
	- aserver: The client sends a hash from a different address than it used to retrieve the nonce.
	- aserver: The client sends the wrong hash of secret and nonce.
	- fserver: The client sends a fortune nonce from a different address than it used in communicating with the aserver.
	- fserver: The client sends an incorrect fortune nonce.
	- The aserver should respond with a NonceMessage to all UDP packets that are not of HashMessage type.
 - All messages must fit into 1024 bytes.
 
 
 
 
<h3>
	<b>Assumptions You Can Make</b>
</h3>

 - Both servers have an unlimited amount of memory to support an unbounded number 
	of outstanding client connections.
 - The fserver can assume that there is a single connecting aserver (over RPC).
 - Once started the aserver and fserver never fail.
 - The fserver is run before the aserver.
 - Your implementation does not need to survive internal errors, such as errors that 
	arise during marshalling of JSON messages, in RPC communication, etc.
	
	
<h3>
	<b>Solution Spec</b>
</h3>

Write two go programs, auth-server.go and fortune-server.go, that implement the description above. 
These programs must conform to the following command line usage:

go run auth-server.go [aserver UDP ip:port] [fserver RPC ip:port] [secret]

- [aserver UDP ip:port] : the UDP address on which the aserver receives new client connections
- [fserver RPC ip:port] : the TCP address on which the fserver listens to RPC connections from the aserver
- [secret] : an int64 secret

go run fortune-server.go [fserver RPC ip:port] [fserver UDP ip:port]
- [fserver RPC ip:port] : the TCP address on which the fserver listens to RPC connections from the aserver
- [fserver UDP ip:port] : the UDP address on which the fserver receives client connections