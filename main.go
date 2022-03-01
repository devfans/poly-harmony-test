package main

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/harmony-one/harmony/block"
	"github.com/polynetwork/bridge-common/chains/harmony"
)

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

type Helper struct {
	*harmony.Client
}

func NewHelper(url string) *Helper {
	return &Helper{harmony.New(url)}
}

// Harmony Header with Signature
type HeaderWithSig struct {
	HeaderRLP []byte
	Sig       []byte
	Bitmap    []byte
}

func (h *Helper) GetHeader(height uint64) (*block.Header, []byte) {
	bytes, err := h.HeaderByNumberRLP(height)
	checkError(err)
	fmt.Println(hex.EncodeToString(bytes))
	header := new(block.Header)
	err = rlp.DecodeBytes(bytes, header)
	checkError(err)
	nextHeader, err := h.HeaderByNumber(height + 1)
	checkError(err)
	fmt.Println(*nextHeader)
	sig, err := nextHeader.GetLastCommitSignature()
	checkError(err)
	bitmap, err := nextHeader.GetLastCommitBitmap()
	checkError(err)
	hs := harmony.HeaderWithSig{bytes, sig, bitmap}
	hsBytes, err := hs.Encode()
	checkError(err)
	return header, hsBytes
}

func main() {
	h := NewHelper("https://api.harmony.one")
	n := uint64(1785855)
	header, hs := h.GetHeader(n)
	fmt.Printf("\n\nEpoch %s\n rlp: %x\n", header.Epoch(), hs)
}
