package tls

// #cgo darwin CFLAGS: -I${SRCDIR}/darwin_Babassl_lib/include -Wno-deprecated-declarations
// #cgo darwin LDFLAGS: -L${SRCDIR}/darwin_Babassl_lib/lib -lssl -lcrypto
// #cgo linux CFLAGS: -I${SRCDIR}/linux_Babassl_lib/include -Wno-deprecated-declarations
// #cgo linux LDFLAGS: -L${SRCDIR}/linux_Babassl_lib/lib ${SRCDIR}/linux_Babassl_lib/lib/libssl.a ${SRCDIR}/linux_Babassl_lib/lib/libcrypto.a -ldl
import "C"
