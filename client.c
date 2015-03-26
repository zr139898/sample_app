// The client creates a connection to the server on the port
// as specified in common.h.
// Once the connection is established, it reads data from stdin
// until EOF is reached, and sends to the server.
// Make SSL connection, merely provides the authentication info,
// but it does not validate anything about the peer.

#include "common.h"

// both the client cert and client PRK are contained in client.pem
#define CERTFILE "client.pem"

// provides cert to the server
// the default OpenSSL passphrase callback is acceptable
// This example prints errors and exits if anything goes wrong.
SSL_CTX * setup_client_ctx(void) {
    SSL_CTX * ctx = SSL_CTX_new(SSLv23_method());
    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        int_error("Error loading certificate");
    if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
        int_error("Error loading private key from file");
    return ctx;
}

// simple change SSL instead of BIO.
// add a return value, if no errors occur, we can call SSL_shutdown
// to stop the SSL connection; other we call SSL_clear.
// removes the call to BIO_free, coz SSL_free automatically frees the
// SSL object's underlying BIOs for us.
int do_client_loop(SSL * ssl) {
    int err, nwritten;
    char buf[80];

    while (1) {
        if (!fgets(buf, sizeof(buf), stdin))
            break;
        for (nwritten = 0; nwritten < sizeof(buf); nwritten += err) {
            err = SSL_write(ssl, buf + nwritten, strlen(buf) - nwritten);
            if (err <= 0) return 0;
        }
    }
    return 1;
}

int main(int argc, char * argv[]) {
    BIO * conn;
    SSL * ssl;
    SSL_CTX * ctx;

    init_OpenSSL();
    seed_prng();

    ctx = setup_client_ctx();

    conn = BIO_new_connect(SERVER ":" PORT);
    if (!conn) int_error("Error creating connection BIO");

    if (BIO_do_connect(conn) <= 0)
        int_error("Error connecting to remote machine");
    // SSL_new creates SSL object and copies the setting we've already
    // placed in the SSL_CTX to the newly created object.
    if (!(ssl = SSL_new(ctx)))
        int_error("Error creating an SSL context");
    // SSL objects an perform SSL functions on top of many different
    // types of I/O methods, we must specify a BIO for our object to
    // use. Through a call to SSL_set_bio.
    // Since SSL objects are robust enough to operate on two one-way
    // I/O types instead of requiring a single full-duplex I/O method.
    SSL_set_bio(ssl, conn, conn);
    // SSL_connect causes the SSL object to initiate the protocal
    // using the underlying I/O. It begins the SSL handshake with the
    // application on the other end of the underlying BIO.
    if (SSL_connect(ssl) <= 0)
        int_error("Error connecting SSL object");

    fprintf(stderr, "SSL Connection opened\n");
    if (do_client_loop(ssl))
        SSL_shutdown(ssl);
    else
        SSL_clear(ssl);
    fprintf(stderr, "SSL Connection closed\n");

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

