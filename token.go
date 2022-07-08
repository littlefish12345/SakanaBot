package FishBot

type Token struct {
	TlvType0x104Data []byte
	TlvType0x133Data []byte
	TlvType0x174Data []byte
	TlvType0x402Data []byte
	RansSeed         []byte
	Dpwd             []byte
	G                []byte
	PsKeyMap         map[string][]byte
	Pt4TokenMap      map[string][]byte
	LoginBitMap      uint32
	SrmToken         []byte
	Tgt              []byte
	TgtKey           []byte
	UserSTKey        []byte
	UserSTWebSig     []byte
	SKey             []byte
	SKeyExpiredTime  int64
	D2               []byte
	D2Key            []byte
	DeviceToken      []byte
}
