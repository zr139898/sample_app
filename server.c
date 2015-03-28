// server.c -- creates a BIO_s_accept,
// calls BIO_do_accept binds the socket to PORT
// Subsequent calls to BIO_do_accept will block and wait for a remote
// connection.
// When a connection is made, a new thread to handle the new connection is spawned,
// which then calls do_server_loop with the connected socket's BIO.

// SSL-enabled, simply provides its cert info to the client, it's not
// yet secure since it validates nothing about the peer.

#include "common.h"

#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "server.pem"

SSL_CTX * setup_server_ctx(void) {
    SSL_CTX * ctx;

    ctx = SSL_CTX_new(SSLv23_method());
    if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
        int_error("Error loading CA file and/or directory");
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        int_error("Error loading default CA file and/or directory");
    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        int_error("Error loading certificate from file");
    if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
        int_error("Error loading private key from file");
    // a client cert is required.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    return ctx;
}

int do_server_loop(SSL *ssl) {
    int err, nread;
    char buf[80];

    do {
        for (nread = 0; nread < sizeof(buf); nread += err) {
            err = SSL_read(ssl, buf + nread, sizeof(buf) - nread);
            if (err <= 0) break;
        }
        fprintf(stdout, "%s", buf);
    }
    while (err > 0);
    // use a call to SSL_get_shutdown to check into the error status
    // of the SSL object. This allows us to differentiate normal
    // client terminations from actual errors.
    // If SSL_RECEIVERD_SHUTDOWN flag is set, we knowthe session
    // hasn't had an error and it's safe to cache. In other words,
    // we can call SSL_shutdown rather simply clear the connection.
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}

void THREAD_CC server_thread(void * arg) {
    SSL * ssl = (SSL *) arg;
    long err;
    
#ifndef WIN32
    pthread_detach(pthread_self());
#endif
    // SSL_accept initiates communication on the underlying I/O layer
    // to perform the SSL handshake.
    if (SSL_accept(ssl) <= 0)
        int_error("Error accepting SSL connection");
    if ((err = post_connection_check(ssl, CLIENT)) != X509_V_OK) {
        fprintf(stderr, "-Error: peer certificate: %s\n",
                X509_verify_cert_error_string(err));
        int_error("Error checking SSL object after connection");
    }
    fprintf(stderr, "SSL Connection opened\n");
    if (do_server_loop(ssl))
        SSL_shutdown(ssl);
    else
        SSL_clear(ssl);
    fprintf(stderr, "SSL Connection closed\n");
    SSL_free(ssl);
    ERR_remove_state(0);
#ifdef WIN32
    _endthread();
#endif
}

int main(int argc, char * argv[]) {
    BIO * acc, * client;
    THREAD_TYPE tid;
    SSL * ssl;
    SSL_CTX * ctx;

    init_OpenSSL();
    seed_prng();

    ctx = setup_server_ctx();
    
    acc = BIO_new_accept(PORT);
    if (!acc)
        int_error("Error creating server socket");
    if (BIO_do_accept(acc) <= 0)
        int_error("Error binding server socket");
    // BIO_do_accept() will block and wait for a remote connection.
    while (1) {
        if (BIO_do_accept(acc) <= 0)
            int_error("Error accepting connection");
        // get the client BIO
        client = BIO_pop(acc);
        if (!(ssl = SSL_new(ctx)))
            int_error("Error creating SSL context");
        SSL_set_accept_state(ssl);
        SSL_set_bio(ssl, client, client);
        // create a new thread to handle the new connection,
        // The thread will call do_server_loop with the client BIO.
        // THREAD_CREATE(tid, entry, arg);
        // tid is the id of the new thread.
        // server_thread is the function defined above, which will call
        // do_server_loop() with the client BIO.
        THREAD_CREATE(tid, (void *)server_thread, ssl);
    }
    SSL_CTX_free(ctx);
    BIO_free(acc);
    return 0;
}



