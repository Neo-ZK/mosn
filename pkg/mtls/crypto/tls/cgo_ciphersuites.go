package tls

// #include "shim.h"
import "C"
import (
	"errors"
	"strings"
)

type Ciphersuites struct {
	id   uint16
	name string
}

var Tls12Cipher = []*Ciphersuites{
	{TLS_RSA_WITH_RC4_128_SHA, "RC4-SHA"},
	{TLS_RSA_WITH_3DES_EDE_CBC_SHA, "DES-CBC3-SHA"},
	{TLS_RSA_WITH_AES_128_CBC_SHA, "AES128-SHA"},
	{TLS_RSA_WITH_AES_256_CBC_SHA, "AES256-SHA"},
	{TLS_RSA_WITH_AES_128_CBC_SHA256, "AES128-SHA256"},
	{TLS_RSA_WITH_AES_128_GCM_SHA256, "AES128-GCM-SHA256"},
	{TLS_RSA_WITH_AES_256_GCM_SHA384, "AES256-GCM-SHA384"},
	{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "ECDHE-ECDSA-RC4-SHA"},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "ECDHE-ECDSA-AES128-SHA"},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "ECDHE-ECDSA-AES256-SHA"},
	{TLS_ECDHE_RSA_WITH_RC4_128_SHA, "ECDHE-RSA-RC4-SHA"},
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "ECDHE-RSA-DES-CBC3-SHA"},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "ECDHE-RSA-AES128-SHA"},
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "ECDHE-RSA-AES256-SHA"},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256"},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "ECDHE-RSA-AES128-SHA256"},
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "ECDHE-RSA-AES128-GCM-SHA256"},
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ECDHE-ECDSA-AES128-GCM-SHA256"},
	{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "ECDHE-RSA-AES256-GCM-SHA384"},
	{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "ECDHE-ECDSA-AES256-GCM-SHA384"},
	{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, "ECDHE-RSA-CHACHA20-POLY1305"},
	{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, "ECDHE-ECDSA-CHACHA20-POLY1305"},
}

var Tls13Cipher = []*Ciphersuites{
	{TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
	{TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
	{TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
	{TLS_SM4_GCM_SM3, "TLS_SM4_GCM_SM3"},
	{TLS_SM4_CCM_SM3, "TLS_SM4_CCM_SM3"},
}

func SslCtxSetCiphersuites(ctx *C.SSL_CTX, cipherSuites []uint16) error {
	tls12cipherString := ""
	tls13cipherString := ""
	C.SSL_CTX_set_security_level(ctx, 0)
	for _, id := range cipherSuites {
		for _, tls12ciph := range Tls12Cipher {
			if id == tls12ciph.id {
				tls12cipherString += tls12ciph.name
				tls12cipherString += ":"
			}
		}

		for _, tls13ciph := range Tls13Cipher {
			if id == tls13ciph.id {
				tls13cipherString += tls13ciph.name
				tls13cipherString += ":"
			}
		}
	}
	if tls12cipherString != "" {
		tls12cipherString = strings.TrimRight(tls12cipherString, ":")
		ret := C.SSL_CTX_set_cipher_list(ctx, C.CString(tls12cipherString))
		if int(ret) <= 0 {
			return errors.New("set tls12 cipher error")
		}
	}
	if tls13cipherString != "" {
		tls13cipherString = strings.TrimRight(tls13cipherString, ":")
		ret := C.SSL_CTX_set_ciphersuites(ctx, C.CString(tls13cipherString))
		if int(ret) <= 0 {
			return errors.New("set tls13 cipher error")
		}
	}

	return nil
}

//Actually we have to manually set all cipher support for server, especially for weak cipher,
//because openssl reject weak default
func SslCtxSetDefaultCipher(ctx *C.SSL_CTX) error {
	tls12cipherString := ""
	tls13cipherString := ""
	for _, tls12ciph := range Tls12Cipher {
		tls12cipherString += tls12ciph.name
		tls12cipherString += ":"
	}

	for _, tls13ciph := range Tls13Cipher {
		tls13cipherString += tls13ciph.name
		tls13cipherString += ":"
	}

	if tls12cipherString != "" {
		tls12cipherString = strings.TrimRight(tls12cipherString, ":")
		ret := C.SSL_CTX_set_cipher_list(ctx, C.CString(tls12cipherString))
		if int(ret) <= 0 {
			return errors.New("set tls12 cipher error")
		}
	}
	if tls13cipherString != "" {
		tls13cipherString = strings.TrimRight(tls13cipherString, ":")
		ret := C.SSL_CTX_set_ciphersuites(ctx, C.CString(tls13cipherString))
		if int(ret) <= 0 {
			return errors.New("set tls13 cipher error")
		}
	}
	return nil
}
