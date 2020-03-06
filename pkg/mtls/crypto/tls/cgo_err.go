package tls

/*
#include "shim.h"

int get_ssl_err(void *res)
{
	unsigned long l;
	char buf[256];
	char *buf2 = res;
    const char *file, *data;
	int line, flags;
	int writeLen = 0;

	union {
        CRYPTO_THREAD_ID tid;
        unsigned long ltid;
    } tid;

    tid.ltid = 0;
    tid.tid = CRYPTO_THREAD_get_current_id();

    while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        ERR_error_string_n(l, buf, sizeof(buf));
        writeLen = BIO_snprintf(buf2, 4096, "%lu:%s:%s:%d:%s\n", tid.ltid, buf,
                                file, line, (flags & ERR_TXT_STRING) ? data : "");
	}

	return writeLen;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

const (
	SslErrWantRead   int = 0
	SslErrWantWrite  int = 1
	SslErrZeroReturn int = 2
	SslErrSsl        int = 3
)

type BabasslErr struct {
	ErrType int
	Msg     string
}

func (sslErr *BabasslErr) Error() string {
	return fmt.Sprintf("error type is %d, error msg is: %s", sslErr.ErrType, sslErr.Msg)
}

func SslGenStandardError(errType int, msg string) *BabasslErr {
	return &BabasslErr{
		ErrType: errType,
		Msg:     msg,
	}
}

func getSslError() string {
	buf := make([]byte, 4096)
	writeLen := C.get_ssl_err(unsafe.Pointer(&buf[0]))
	res := buf[:writeLen]
	return *(*string)(unsafe.Pointer(&res))
}
