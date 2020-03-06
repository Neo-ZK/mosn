package tls

/*
#include "shim.h"

static char *get_ssl_alpn_info(SSL *ssl)
{
	char **alpn;
	unsigned len;
	BABASSL_get0_alpn_proposed(ssl, (const unsigned char**)alpn, &len);
	if (len != 0) {
		return *alpn;
	}
	return NULL;
}

static int SSL_client_hello_servername_ext_to_gostring(SSL *s, void *gostring)
{
	const unsigned char *p = NULL;
	const char *servername;
	int ret = 0;
	size_t len, remaining;

	ret = SSL_client_hello_get0_ext(s, TLSEXT_TYPE_server_name, &p, &remaining);
	if (ret <= 0 || remaining <= 2) {
		return 0;
	}

	// Extract the length of the supplied list of names.
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 != remaining)
        return 0;
    remaining = len;

	// The list in practice only has a single element, so we only consider
    // the first one.
    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name)
        return 0;
	remaining--;

    //Now we can finally pull out the byte array with the actual hostname.
    if (remaining <= 2)
        return 0;
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 > remaining)
        return 0;
    remaining = len;
    servername = (const char *)p;

	memcpy(gostring, servername, remaining);
	return remaining;
}

static int SSL_client_hello_alpn_ext_to_gostring(SSL *s, void *gostring)
{
	const unsigned char *p = NULL;
	int len = 0;
	int ret = 0;

	ret = SSL_client_hello_get0_ext(s, TLSEXT_TYPE_application_layer_protocol_negotiation,
		                            &p, (size_t *)(&len));
	if (ret <= 0 || len <= 0) {
		return 0;
	}

	memcpy(gostring, p, len);
	return len;
}

*/
import "C"
import (
	"errors"
	"unsafe"

	"mosn.io/mosn/pkg/mtls/crypto/x509"
)

type clientHelloCbParam struct {
	getConfigForClient func(*ClientHelloInfo) (*Config, error)
	getCertificate     func(*ClientHelloInfo) (*Certificate, error)
	certs              []x509.Certificate
}

//export ServerClientHelloCallBackForGetConfigForClient
func ServerClientHelloCallBackForGetConfigForClient(ssl *C.SSL, al *C.int, arg unsafe.Pointer) C.int {
	var tmp Config
	cb, ok := cgoPointerRestore(arg).(func(*ClientHelloInfo) (*Config, error))
	cgoPointerUnref(arg)
	if !ok {
		return -1
	}
	//transfer babassl info to go-native tls.ClientHelloInfo
	ch := transferBabasslInfoToTlsClientHelloInfo(ssl)
	//call go-native GetConfigForClient
	tlsConfig, err := cb(&ch)
	if err != nil {
		return -1
	}
	tmp = *tlsConfig
	_ = tmp
	//else choose right certificate

	//transfer tls.ClientHelloInfo to babassl info and set
	err = setTlsConfigInfoToSsl(ssl, tlsConfig)
	if err != nil {
		return -1
	}
	return 1
}

func setTlsConfigInfoToSsl(ssl *C.SSL, conf *Config) error {
	ctx := C.SSL_get_SSL_CTX(ssl)
	ctxErr := setTlsConfigInfoToSslCtx(ctx, conf)
	if ctxErr != nil {
		return ctxErr
	}
	if len(conf.Certificates) != 0 {
		cert := conf.Certificates[0].BabasslCert.Cert
		if cert != nil {
			if int(C.SSL_use_certificate(ssl, cert)) <= 0 {
				return errors.New("error happen in setTlsConfigInfoToSsl set cert")
			}
		}
		pkey := conf.Certificates[0].BabasslCert.Pkey
		if pkey != nil {
			if int(C.SSL_use_PrivateKey(ssl, pkey)) <= 0 {
				return errors.New("error happen in setTlsConfigInfoToSsl set cert")
			}
		}
	}

	if conf.ClientAuth == RequestClientCert || conf.ClientAuth == RequireAnyClientCert {
		C.SSL_set_verify(ssl, C.SSL_VERIFY_PEER|C.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nil)
		//to do
		//set a verifycallback always return 1
	} else if conf.ClientAuth == VerifyClientCertIfGiven {
		C.SSL_set_verify(ssl, C.SSL_VERIFY_PEER, nil)
	} else if conf.ClientAuth == RequireAndVerifyClientCert {
		C.SSL_set_verify(ssl, C.SSL_VERIFY_PEER|C.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nil)
	}

	if conf.ClientCAs != nil {
		clientCAS, err := TranslateGoCertsToSslX509s(conf.ClientCAs.GetCerts())
		if err != nil {
			return err
		}
		err = SetVerifyCertsIntoSsl(ssl, clientCAS)
		if err != nil {
			return err
		}
	}

	return nil
}

func setTlsConfigInfoToSslCtx(ctx *C.SSL_CTX, conf *Config) error {
	if conf.VerifyPeerCertificate != nil {
		configPtr := cgoPointerSave(conf)
		C.ssl_ctx_set_cert_verify_callback_ServerVerifyBackForVerifyPeerCertificate(ctx, configPtr)
	}
	return nil
}

func transferBabasslInfoToTlsClientHelloInfo(ssl *C.SSL) ClientHelloInfo {
	ch := ClientHelloInfo{}

	//servername
	servername_buf := make([]byte, 4096)
	servername_len := int(C.SSL_client_hello_servername_ext_to_gostring(ssl,
		unsafe.Pointer(&servername_buf[0])))
	if servername_len > 0 {
		servername := BytesToString(servername_buf[:servername_len])
		ch.ServerName = servername
	}

	//todo
	//ch.CipherSuites =
	//ch.SupportedCurves
	//ch.SupportedPoints=
	//ch.SignatureSchemes
	alpn_buf := make([]byte, 4096)
	alpn_len := int(C.SSL_client_hello_alpn_ext_to_gostring(ssl, unsafe.Pointer(&servername_buf[0])))
	alpn := BytesToString(alpn_buf[:alpn_len])
	//alpnC := C.get_ssl_alpn_info(ssl)
	//todo translate alpnC(char *) to []gostring
	if alpn != "" {
		ch.SupportedProtos = []string{alpn}
	}
	//ch.SupportedProtos = C.GoString(alpn)
	//ch.SupportedVersions
	return ch

}

//export ServerVerifyBackForVerifyPeerCertificate
func ServerVerifyBackForVerifyPeerCertificate(xs *C.X509_STORE_CTX, arg unsafe.Pointer) C.int {
	conf, ok := cgoPointerRestore(arg).(*Config)
	cgoPointerUnref(arg)
	if !ok {
		return -1
	}

	if conf.VerifyPeerCertificate != nil {
		//get peer cert chain
		untrustChain := C.X509_STORE_CTX_get0_untrusted(xs)
		peerCerts, err := TranslateSslX509StackToGoCerts(untrustChain)
		if err != nil {
			return -1
		}
		peerCertsRaw, rawErr := TranslateSslX509StackToRawBytes(untrustChain)
		if rawErr != nil {
			return -1
		}

		if conf.ClientAuth >= VerifyClientCertIfGiven && len(peerCerts) > 0 {
			opts := x509.VerifyOptions{
				Roots:         conf.ClientCAs,
				CurrentTime:   conf.time(),
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}

			for _, cert := range peerCerts[1:] {
				opts.Intermediates.AddCert(cert)
			}

			chains, err := peerCerts[0].Verify(opts)
			if err != nil {
				return -1
			}

			if err := conf.VerifyPeerCertificate(peerCertsRaw, chains); err != nil {
				return -1
			}
		}
	}
	return 1
}
