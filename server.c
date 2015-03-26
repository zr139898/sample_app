// server.c -- creates a BIO_s_accept,
// calls BIO_do_accept binds the socket to PORT
// Subsequent calls to BIO_do_accept will block and wait for a remote
// connection.
// When a connection is made, a new thread to handle the new connection is spawned,
// which then calls do_server_loop with the connected socket's BIO.

#include "common.h"

void do_server_loop(BIO * conn) {
    int err, nread;
    char buf[80];

    do {
        for (nread = 0; nread < sizeof(buf); nread += err) {
            err = BIO_read(conn, buf + nread, sizeof(buf) - nread);
            if (err <= 0) break;
        }
        fwrite(buf, 1, nread, stdout);
    }
    while (error > 0)  continue;
}

void THREAD_CC server_thread(void * arg) {
    BIO * client = (BIO *) arg;

#ifndef WIN32
    pthread_detach(pthread_self());
#endif
    fprintf(stderr, "Connection opened.\n");
    do_server_loop(client);
    fprintf(stderr, "Connection closed.\n");

    BIO_free(client);
    ERR_remove_state(0);
#ifdef WIN32
    _endthread();
#endif
}

int main(int argc, int * argv[]) {
    BIO * acc, * client;
    THREAD_TYPE tid;

    init_OpenSSL();

    acc = BIO_new_accept(PORT);
    if (!acc)
        int_error("Error creating server socket");
    if (BIO_do_accept(acc) <= 0)
        int_error("Error binding server socket");
    while (1) {
        if (BIO_do_accept(acc) <= 0)
            int_error("Error accepting connection");

        client = BIO_pop(acc);
        THREAD_CREATE(tid, server_thread, client);
    }
    BIO_free(acc);
    return 0;
}

