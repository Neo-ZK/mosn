package tls

// #include "shim.h"
import "C"

import (
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"unsafe"
)

const (
	SSLRecordSize = 65536
)

func nonCopyGoBytes(ptr uintptr, length int) []byte {
	var slice []byte
	header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	header.Cap = length
	header.Len = length
	header.Data = ptr
	return slice
}

func nonCopyCString(data *C.char, size C.int) []byte {
	return nonCopyGoBytes(uintptr(unsafe.Pointer(data)), int(size))
}

type WriteBio struct {
	data_mtx        sync.Mutex
	op_mtx          sync.Mutex
	buf             []byte
	release_buffers bool
	conn            net.Conn
	mtx             *sync.Mutex
	err             error
}

func loadWritePtr(b *C.BIO) *WriteBio {
	//t := token(C.X_BIO_get_data(b))
	return (*WriteBio)(C.X_BIO_get_data(b))
}

func bioClearRetryFlags(b *C.BIO) {
	C.X_BIO_clear_flags(b, C.BIO_FLAGS_RWS|C.BIO_FLAGS_SHOULD_RETRY)
}

func bioSetRetryRead(b *C.BIO) {
	C.X_BIO_set_flags(b, C.BIO_FLAGS_READ|C.BIO_FLAGS_SHOULD_RETRY)
}

//export go_write_bio_write
func go_write_bio_write(b *C.BIO, data *C.char, size C.int) (rc C.int) {
	ptr := loadWritePtr(b)
	if ptr == nil || data == nil || size < 0 {
		return -1
	}
	bioClearRetryFlags(b)
	ptr.err = nil
	sourceBuf := nonCopyCString(data, size)
	ptr.mtx.Unlock()
	n, err := ptr.conn.Write(sourceBuf)
	ptr.mtx.Lock()
	if err != nil {
		ptr.err = err
		return C.int(-1)
	}
	return C.int(n)
}

//export go_write_bio_ctrl
func go_write_bio_ctrl(b *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) (
	rc C.long) {
	defer func() {
		if err := recover(); err != nil {
			if BabasslPrintTraceTag.IsOpen() {
				print("openssl: writeBioCtrl panic'd: %v", err)
			}
			rc = -1
		}
	}()
	switch cmd {
	case C.BIO_CTRL_WPENDING:
		return writeBioPending(b)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		return 1
	default:
		return 0
	}
}

func writeBioPending(b *C.BIO) C.long {
	ptr := loadWritePtr(b)
	if ptr == nil {
		return 0
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	return C.long(len(ptr.buf))
}

func (b *WriteBio) MakeCBIO() *C.BIO {
	rv := C.X_BIO_new_write_bio()
	C.BIO_set_data(rv, unsafe.Pointer(b))
	return rv
}

type ReadBio struct {
	data_mtx        sync.Mutex
	op_mtx          sync.Mutex
	conn            net.Conn
	buf             []byte
	readIndex       int
	writeIndex      int
	notClear        bool
	eof             bool
	release_buffers bool
	mtx             *sync.Mutex
	err             error
}

func loadReadPtr(b *C.BIO) *ReadBio {
	return (*ReadBio)(C.X_BIO_get_data(b))
}

//export go_read_bio_read
func go_read_bio_read(b *C.BIO, data *C.char, size C.int) (rc C.int) {

	ptr := loadReadPtr(b)
	if ptr == nil || size < 0 {
		return C.int(-1)
	}

	bioClearRetryFlags(b)
	ptr.err = nil
	conn := ptr.conn
	targetBuf := nonCopyCString(data, size)
	ptr.mtx.Unlock()
	n, err := conn.Read(targetBuf)
	ptr.mtx.Lock()
	//for raw bytes
	if cap(ptr.buf) < n {
		ptr.buf = make([]byte, n+SSLRecordSize)
	}
	copy(ptr.buf, targetBuf)
	if err != nil {
		ptr.err = err
		return C.int(-1)
	}

	return C.int(n)
}

//export go_read_bio_ctrl
func go_read_bio_ctrl(b *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) (
	rc C.long) {

	defer func() {
		if err := recover(); err != nil {
			if BabasslPrintTraceTag.IsOpen() {
				print("openssl: readBioCtrl panic'd: %v", err)
			}
			rc = -1
		}
	}()
	switch cmd {
	case C.BIO_CTRL_PENDING:
		return readBioPending(b)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		return 1
	default:
		return 0
	}
}

func readBioPending(b *C.BIO) C.long {
	ptr := loadReadPtr(b)
	if ptr == nil {
		return 0
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	return C.long(len(ptr.buf))
}

func (b *ReadBio) getRawInput() []byte {
	return b.buf
}

func (b *ReadBio) MakeCBIO() *C.BIO {
	rv := C.X_BIO_new_read_bio()
	C.X_BIO_set_data(rv, unsafe.Pointer(b))
	return rv
}

func (b *ReadBio) MarkEOF() {
	b.data_mtx.Lock()
	defer b.data_mtx.Unlock()
	b.eof = true
}

type anyBio C.BIO

func asAnyBio(b *C.BIO) *anyBio { return (*anyBio)(b) }

func (b *anyBio) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n = int(C.X_BIO_read((*C.BIO)(b), unsafe.Pointer(&buf[0]), C.int(len(buf))))
	if n <= 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (b *anyBio) Write(buf []byte) (written int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := int(C.X_BIO_write((*C.BIO)(b), unsafe.Pointer(&buf[0]),
		C.int(len(buf))))
	if n != len(buf) {
		return n, errors.New("BIO write failed")
	}
	return n, nil
}
