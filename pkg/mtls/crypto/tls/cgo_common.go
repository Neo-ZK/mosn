package tls

import (
	"errors"
	"reflect"
	"sync"
	"unsafe"
)

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

//use to determine whether use babassl, default close
var useBabasslTag = &BabasslTag{
	tag: true,
}

func OpenBabasslTag() {
	useBabasslTag.Open()
}

func CloseBabasslTag() {
	useBabasslTag.Close()
}

//use to determine whether open print trace, default close
var BabasslPrintTraceTag = &BabasslTag{
	tag: false,
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

func PacketPeek2byteToLen(packet []byte) (uint16, error) {
	if len(packet) < 2 {
		return 0, errors.New("PacketPeek2byteToLen error, packet less than 2 byte")
	}

	res := uint16(packet[0]) << 8
	res |= uint16(packet[1])

	return res, nil
}

func PacketPeek1byteToLen(packet []byte) (uint8, error) {
	if len(packet) < 1 {
		return 0, errors.New("PacketPeek1byteToLen error, packet less than 1 byte")
	}

	res := uint8(packet[0])

	return res, nil
}
