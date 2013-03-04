Steps to use the DTLS library on node.js

****Important******: Copy the libopenssl.a library from node deps folder to /usr/lib/

Supported OS: Linux.
Author: Sayyad Gaffar.
Node Version: >= 0.6.0
Installtion: npm i node_dtls

To test DTLS on Node:

a) DTLS macros needs to be disabled on openssl configuration file.
	1) Comment out the macro:
 
			#'OPENSSL_NO_DTLS1',
        		#'OPENSSL_NO_SOCK',
        		#'OPENSSL_NO_DGRAM',
				
			in openssl.gyp  Path: /node directory/deps/openssl/openssl.gyp
	
b) Make the changes in openssl as mentioned in the below patch:

			http://cvs.openssl.org/filediff?f=openssl/ssl/s3_pkt.c&v1=1.72.2.7.2.11&v2=1.72.2.7.2.12 

c) Recompile node with the above settings.
			a) ./configure.
			b) make
			c) make install

d) Testing the dtls on node

		a) In the node_modules folder, find dtls.
		b) Inside Demo, one will find the dtlsserver and dtlsclient.
		c) Run the dtls Server: dtls/demo/dtlsServer/dtlsController.js  
		d) Connect using the dtls client: dtls/demo/dtlsClient.js
		e) The certificate and key are generated using openssl to test the dtls client and server.

To run the Client Install the below modules.

a) bindings.
b) microtime.
c) log4js.
d) nodeload.


