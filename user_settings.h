#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef _WIN32
#define USE_WOLFSSL_IO
#endif

#define WOLFSSL_WOLFSSH
#define WOLFCRYPT_ONLY
#define WOLFSSL_KEY_GEN
#define HAVE_ECC
#define HAVE_AESGCM
#define HAVE_HASHDRBG
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define NO_PSK
#define NO_HC128
#define NO_RC4
#define NO_RABBIT
#define NO_DSA
#define NO_MD4
#define WC_RSA_BLINDING
#define WOLFSSL_PUBLIC_MP
#define WC_NO_HARDEN

#endif
