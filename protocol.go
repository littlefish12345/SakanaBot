package FishBot

var (
	AndroidPad = Protocol{
		ApkId:      "com.tencent.minihd.qq",
		AppId:      16,
		SubAppId:   537065739,
		Version:    "5.8.9",
		ApkSign:    []byte{0xAA, 0x39, 0x78, 0xE0, 0x1F, 0xD9, 0x6F, 0xF9, 0x91, 0x4A, 0x66, 0x9E, 0x18, 0x64, 0x74, 0xC7},
		BuildTime:  1595836208,
		SdkVersion: "6.0.0.2433",
		SsoVersion: 12,
		Bitmap:     150470524,
		MainSigmap: 1970400,
		SubSigmap:  0x10400,
		Name:       "AndroidPad",
	}
	ProtocolMap = map[string]*Protocol{
		"AndroidPad": &AndroidPad,
	}
)

type Protocol struct {
	ApkId      string
	AppId      uint32
	SubAppId   uint32
	Version    string
	ApkSign    []byte
	BuildTime  uint32
	SdkVersion string
	SsoVersion uint32
	Bitmap     uint32
	MainSigmap uint32
	SubSigmap  uint32
	Name       string
}

func getProtocol(name string) *Protocol {
	return ProtocolMap[name]
}
