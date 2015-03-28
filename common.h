#ifndef COMMON_H_
#define COMMON_H_
// common.h -- includes relevant headers from OpenSSL.
// define the strings for the client and server machines as well as
// the server's listening port.
// Some definitions for convenient error handling and for threading in
// a platform-independent manner.

#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include "ssl_multithread.h"

#ifndef WIN32
#include <pthread.h>
#define THREAD_CC
#define THREAD_TYPE pthread_t
#define THREAD_CREATE(tid, entry, arg) pthread_create(&(tid), NULL, \
                                                      (entry), (arg))
#else
#include <windows.h>
#define THREAD_CC __cdecl
#define THREAD_TYPE DWORD
#define THREAD_CREATE(tid, entry, arg) do { _beginthread((entry), 0, (arg)); \
        (tid) = GetCurrentThreadId();                                   \
    } while (0)
#endif

#define PORT "6001"
#define SERVER "splat.zork.org"
#define CLIENT "shell.zork.org"

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

void handle_error(const char * file, int lineno, const char * msg);

void init_OpenSSL(void);

void seed_prng(void);

int verify_callback(int preverify_ok, X509_STORE_CTX * ctx);

long post_connection_check(SSL * ssl, char * host);

#endif