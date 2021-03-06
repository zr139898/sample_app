In Step 1, we need server.pem, client.pem and root.pem.

To demonstrate how a chain can grow and still be verifiable, we will creates a server CA. This CA will be signed by the root CA and it will used to sign all server identity certs.
The client cert will be signed directly by the root CA.

==================================================
To creates the root CA:
passphrase of rootkey.pem = root
challenge password of rootreq.pem = rootroot
The conf file is the default aside from including subjectAltName=DNS:FQDN under the certificate extensions section (usr_cert).

$ openssl req -newkey rsa:1024 -sha1 -keyout rootkey.pem -out rootreq.pem
$ openssl x509 -req -in rootreq.pem -sha1 -extfile myopenssl.conf \
    -extensions v3_ca -signkey rootkey.pem -out rootcert.pem
$ cat rootcert.pem rootkey.pem > root.pem
$ openssl x509 -subject -issuer -noout -in root.pem

==================================================
To creates the server CA and sign it with the root CA:
passphrase of serverCAkey.pem = serverca
challenge password of serverCAreq.pem = servercaserverca

$ openssl req -newkey rsa:1024 -sha1 -keyout serverCAkey.pem -out serverCAreq.pem
$ openssl x509 -req -in serverCAreq.pem -sha1 -extfile myopenssl.conf -extensions v3_ca -CA root.pem -CAkey root.pem -CAcreateserial -out serverCAcert.pem
$ cat serverCAcert.pem serverCAkey.pem rootcert.pem > serverCA.pem 
$ openssl x509 -subject -issuer -noout -in serverCA.pem

==================================================
To creates the server's certificate and sign it with the Server CA:
passphrase of serverkey.pem = server
challenge password of serverreq.pem = serverserver

$ openssl req -newkey rsa:1024 -sha1 -keyout serverkey.pem -out serverreq.pem
$ openssl x509 -req -in serverreq.pem -sha1 -extfile myopenssl.conf -extensions usr_cert -CA serverCA.pem -CAkey serverCA.pem -CAcreateserial -out servercert.pem
$ cat servercert.pem serverkey.pem serverCAcert.pem rootcert.pem > server.pem
$ openssl x509 -subject -issuer -noout -in server.pem

==================================================
To creates the client certificate and sign it with the Root CA:
$ openssl req -newkey rsa:1024 -sha1 -keyout clientkey.pem -out clientreq.pem
$ openssl x509 -req -in clientreq.pem -sha1 -extfile myopenssl.conf -extensions usr_cert -CA root.pem -CAkey root.pem -CAcreateserial -out clientcert.pem
$ cat clientcert.pem clientkey.pem rootcert.pem > client.pem
$ openssl x509 -subject -issuer -noout -in client.pem

==================================================
DH paramters (dh512.pem and dh1024.pem)
$ openssl dhparam -check -text -5 512 -out dh512.pem
$ openssl dhparam -check -text -5 1024 -out dh1024.pem

======================================================================
==========Step 2: Peer Authentication
======================================================================
