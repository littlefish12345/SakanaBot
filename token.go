package FishBot

type Token struct {
	TlvType0x104Data []byte
	TlvType0x174Data []byte
	RansSeed         []byte
	TlvType0x402Data []byte
	Dpwd             []byte
	G                []byte
}
