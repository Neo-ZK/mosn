package tls

/*
#include "shim.h"

unsigned char *next_protos_parse(unsigned int *outlen, const char *in)
{
    size_t len;
    unsigned char *out;
    size_t i, start = 0;
    size_t skipped = 0;

    len = strlen(in);
    if (len == 0 || len >= 65535)
        return NULL;

    out = OPENSSL_malloc(len + 1);
    for (i = 0; i <= len; ++i) {
        if (i == len || in[i] == ',') {
            if (i == start) {
                ++start;
                ++skipped;
                continue;
            }
            if (i - start > 255) {
                OPENSSL_free(out);
                return NULL;
            }
            out[start-skipped] = (unsigned char)(i - start);
            start = i + 1;
        } else {
            out[i + 1 - skipped] = in[i];
        }
    }

    if (len <= skipped) {
        OPENSSL_free(out);
        return NULL;
    }

    *outlen = len + 1 - skipped;
    return out;
}

typedef struct tlsextalpnctx_st {
    unsigned char *data;
    unsigned int len;
} tlsextalpnctx;

int alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *arg)
{
    tlsextalpnctx *alpn_ctx = arg;
    if (SSL_select_next_proto
        ((unsigned char **)out, outlen, alpn_ctx->data, alpn_ctx->len, in,
         inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

//The call back function alpn_cb function can not be set into ctx direct
//in go code, because their complie unit are nor same
void set_alpn_cb_to_ctx(SSL_CTX *ctx, void *args)
{
	SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, args);
}

char *get_ssl_alpn_select(SSL *ssl)
{
	char *alpn;
	unsigned int len;
	SSL_get0_alpn_selected(ssl, (const unsigned char **)(&alpn), &len);
	if (len == 0) {
		return NULL;
	}
	return alpn;
}

*/
import "C"
import (
	"errors"
	"unsafe"
)

func clientSslCtxSetAlpnProtos(ctx *C.SSL_CTX, NextProtos []string) error {
	alpnProtos := ""
	for _, str := range NextProtos {
		alpnProtos += str
		alpnProtos += ","
	}
	len := C.uint(1)
	alpn := C.next_protos_parse(&len, C.CString(alpnProtos))
	if alpn == nil {
		return errors.New("client set alpn protos error")
	}
	ret := C.SSL_CTX_set_alpn_protos(ctx, alpn, len)
	if int(ret) != 0 {
		return errors.New("client set alpn protos error")
	}
	return nil
}

func serverSslCtxSetAlpnProtos(ctx *C.SSL_CTX, NextProtos []string) error {
	alpnProtos := ""
	for _, str := range NextProtos {
		alpnProtos += str
		alpnProtos += ","
	}
	len := C.uint(1)
	alpn := C.next_protos_parse(&len, C.CString(alpnProtos))
	if alpn == nil {
		return errors.New("server set alpn protos error")
	}
	var alpnctx C.tlsextalpnctx
	alpnctx.data = alpn
	alpnctx.len = len

	C.set_alpn_cb_to_ctx(ctx, unsafe.Pointer(&alpnctx))

	return nil
}

func getSslAlpnNegotiated(ssl *C.SSL) (string, bool) {
	proto := C.get_ssl_alpn_select(ssl)
	var NegotiatedProtocol string
	var isMutual bool
	if proto != nil {
		NegotiatedProtocol = C.GoString(proto)
		isMutual = true
	} else {
		NegotiatedProtocol = ""
		isMutual = false
	}

	return NegotiatedProtocol, isMutual
}
