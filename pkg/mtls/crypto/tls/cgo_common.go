package tls

import (
	"reflect"
	"sync"
	"unsafe"
)

//use to determine whether use babassl, default close
type BabasslTag struct {
	tag bool
	mtx sync.Mutex
}

func (tag *BabasslTag) Open() {
	tag.mtx.Lock()
	defer tag.mtx.Unlock()
	tag.tag = true
}

func (tag *BabasslTag) Close() {
	tag.mtx.Lock()
	defer tag.mtx.Unlock()
	tag.tag = false
}

func (tag *BabasslTag) IsOpen() bool {
	return tag.tag
}

var useBabasslTag = &BabasslTag{
	tag: true,
}

func OpenBabasslTag() {
	useBabasslTag.Open()
}

func CloseBabasslTag() {
	useBabasslTag.Close()
}

var BabasslPrintTraceTag = &BabasslTag{
	tag: true,
}

func OpenBabasslPrintTraceTag() {
	BabasslPrintTraceTag.Open()
}

func CloseBabasslPrintTraceTag() {
	BabasslPrintTraceTag.Close()
}

func BytesToString(b []byte) string {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh := reflect.StringHeader{bh.Data, bh.Len}
	return *(*string)(unsafe.Pointer(&sh))
}

func StringToBytes(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	bh := reflect.SliceHeader{sh.Data, sh.Len, 0}
	return *(*[]byte)(unsafe.Pointer(&bh))
}
