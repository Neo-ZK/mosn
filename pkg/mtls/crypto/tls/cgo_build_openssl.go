// +build !BabaSSL

package tls

// #cgo darwin CFLAGS: -I${SRCDIR}/darwin_openssl_lib/include -Wno-deprecated-declarations
// #cgo darwin LDFLAGS: -L${SRCDIR}/darwin_openssl_lib/lib -lssl -lcrypto
// #cgo linux CFLAGS: -I${SRCDIR}/linux_openssl_lib/include -Wno-deprecated-declarations
// #cgo linux LDFLAGS: -L${SRCDIR}/linux_openssl_lib/lib ${SRCDIR}/linux_openssl_lib/lib/libssl.a ${SRCDIR}/linux_openssl_lib/lib/libcrypto.a -ldl
import "C"

var Tls13GmCipher = []*Ciphersuites{}
