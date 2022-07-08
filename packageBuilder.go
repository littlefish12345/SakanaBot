package FishBot

import (
	"bytes"
	"strconv"

	goqqtea "github.com/littlefish12345/go-qq-tea"
)

const (
	RequestEncryptEMECDH = uint8(0x00)
	RequestEncryptEMST   = uint8(0x01)

	NetpackRequestTypeLogin  = uint32(0x0A)
	NetpackRequestTypeSimple = uint32(0x0B)
	NetpackEncryptNoEncrypt  = byte(0x00)
	NetpackEncryptD2Key      = byte(0x01)
	NetpackEncryptEmptyKey   = byte(0x02)
)

func (qqClient *QQClient) BuildRequestPack(uin int64, command uint16, encryptMethod uint8, body []byte) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(Int16ToBytes(8001))
	buffer.Write(Int16ToBytes(int16(command)))
	buffer.Write([]byte{0x00, 0x01}) //uint16 0x01
	buffer.Write(Int32ToBytes(int32(uint32(uin))))
	buffer.WriteByte(0x03)
	if encryptMethod == RequestEncryptEMECDH {
		buffer.WriteByte(0x87)
	} else {
		buffer.WriteByte(0x45)
	}
	buffer.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //1*byte+3*uint32

	if encryptMethod == RequestEncryptEMECDH {
		buffer.Write([]byte{0x02, 0x01})
		buffer.Write(qqClient.RandomKey)
		buffer.Write([]byte{0x01, 0x31})
		buffer.Write(Int16ToBytes(int16(qqClient.ECDHKey.ServerPublicKeyVersion)))
		buffer.Write(Int16ToBytes(int16(uint16(len(qqClient.ECDHKey.PublicKey)))))
		buffer.Write(qqClient.ECDHKey.PublicKey)
		buffer.Write(goqqtea.NewTeaCipher(qqClient.ECDHKey.ShareKey).Encrypt(body))
	} else {
		buffer.Write([]byte{0x01, 0x03})
		buffer.Write(qqClient.RandomKey)
		buffer.Write([]byte{0x01, 0x02, 0x00, 0x00}) //2*uint16
		buffer.Write(goqqtea.NewTeaCipher(qqClient.RandomKey).Encrypt(body))
	}
	buffer.WriteByte(0x03)
	return append([]byte{0x02}, append(Int16ToBytes(int16(uint16(buffer.Len()+3))), buffer.Bytes()...)...)
}

func (qqClient *QQClient) BuildNetworkPack(requestType uint32, encryptType byte, seqence uint16, uin int64, commandName string, body []byte) []byte {
	headBuffer := new(bytes.Buffer)
	headBuffer.Write(Int32ToBytes(int32(requestType)))
	headBuffer.WriteByte(encryptType)
	if requestType == NetpackRequestTypeLogin {
		if encryptType == NetpackEncryptD2Key {

		} else {
			headBuffer.Write([]byte{0x00, 0x00, 0x00, 0x04}) //1*uint32
		}
	} else {
		headBuffer.Write(Int32ToBytes(int32(seqence)))
	}
	headBuffer.WriteByte(0x00)
	uinString := strconv.FormatInt(uin, 10)
	headBuffer.Write(Int32ToBytes(int32(uint32(len(uinString) + 4))))
	headBuffer.WriteString(uinString)

	bodyBuffer := new(bytes.Buffer)
	if requestType == NetpackRequestTypeLogin {
		bodyBuffer.Write(Int32ToBytes(int32(seqence)))
		bodyBuffer.Write(Int32ToBytes(int32(qqClient.Device.Protocol.SubAppId)))
		bodyBuffer.Write(Int32ToBytes(int32(qqClient.Device.Protocol.SubAppId)))
		bodyBuffer.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00})
		bodyBuffer.Write([]byte{0x00, 0x00, 0x00, 0x04}) //1*uint32
	}
	bodyBuffer.Write(Int32ToBytes(int32(uint32(len(commandName) + 4))))
	bodyBuffer.WriteString(commandName)
	bodyBuffer.Write(Int32ToBytes(int32(uint32(len(qqClient.SessionId) + 4))))
	bodyBuffer.Write(qqClient.SessionId)
	if requestType == NetpackRequestTypeLogin {
		bodyBuffer.Write(Int32ToBytes(int32(uint32(len(qqClient.Device.IMEI) + 4))))
		bodyBuffer.WriteString(qqClient.Device.IMEI)
		bodyBuffer.Write([]byte{0x00, 0x00, 0x00, 0x04}) //1*uint32
		bodyBuffer.Write(Int16ToBytes(int16(uint16(len(qqClient.Ksid) + 2))))
		bodyBuffer.Write(qqClient.Ksid)
	}
	bodyBuffer.Write([]byte{0x00, 0x00, 0x00, 0x04}) //1*uint32

	bodyEncoded := append(Int32ToBytes(int32(uint32(bodyBuffer.Len()+4))), append(bodyBuffer.Bytes(), append(Int32ToBytes(int32(uint32(len(body)+4))), body...)...)...)
	if encryptType == NetpackEncryptD2Key {

	} else if encryptType == NetpackEncryptEmptyKey {
		key := make([]byte, 16)
		bodyEncoded = goqqtea.NewTeaCipher(key).Encrypt(bodyEncoded)
	}
	headBuffer.Write(bodyEncoded)

	return append(Int32ToBytes(int32(uint32(headBuffer.Len()+4))), headBuffer.Bytes()...)
}

func (qqClient *QQClient) BuildLoginPack() ([]byte, uint16) {
	seqence := qqClient.NextSeqence()
	bodyBuffer := new(bytes.Buffer)
	bodyBuffer.Write(Int16ToBytes(9))  //subCommandId
	bodyBuffer.Write(Int16ToBytes(23)) //tlvNum
	bodyBuffer.Write(TlvType0x18Encode(qqClient.Device.Protocol.AppId, uint32(qqClient.Uin)))
	bodyBuffer.Write(TlvType0x1Encode(uint32(qqClient.Uin), qqClient.Device.IpAddress))
	bodyBuffer.Write(TlvType0x106Encode(uint32(qqClient.Uin), 0, qqClient.Device.Protocol.AppId, qqClient.Device.Protocol.SubAppId, 0, qqClient.Device.Protocol.SsoVersion, qqClient.PaswordHash, true, qqClient.Device.Guid, qqClient.Device.TgtgtKey))
	bodyBuffer.Write(TlvType0x116Encode(qqClient.Device.Protocol.Bitmap, qqClient.Device.Protocol.SubSigmap))
	bodyBuffer.Write(TlvType0x100Encode(qqClient.Device.Protocol.SsoVersion, qqClient.Device.Protocol.AppId, qqClient.Device.Protocol.SubAppId, 0, qqClient.Device.Protocol.MainSigmap))
	bodyBuffer.Write(TlvType0x107Encode(0))
	bodyBuffer.Write(TlvType0x142Encode([]byte(qqClient.Device.Protocol.ApkId)))
	bodyBuffer.Write(TlvType0x144Encode(qqClient.Device, false, true, false))
	bodyBuffer.Write(TlvType0x145Encode(qqClient.Device.Guid))
	bodyBuffer.Write(TlvType0x147Encode(qqClient.Device.Protocol.AppId, []byte(qqClient.Device.Protocol.Version), qqClient.Device.Protocol.ApkSign))
	bodyBuffer.Write(TlvType0x154Encode(seqence))
	bodyBuffer.Write(TlvType0x141Encode([]byte(qqClient.Device.SimInfo), []byte(qqClient.Device.Apn)))
	bodyBuffer.Write(TlvType0x8Encode(2052))
	bodyBuffer.Write(TlvType0x511Encode([]string{
		"tenpay.com", "openmobile.qq.com", "docs.qq.com", "connect.qq.com", "qzone.qq.com", "vip.qq.com",
		"gamecenter.qq.com", "qun.qq.com", "game.qq.com", "qqweb.qq.com", "office.qq.com", "ti.qq.com", "mail.qq.com", "mma.qq.com",
	}))
	bodyBuffer.Write(TlvType0x187Encode([]byte(qqClient.Device.MacAddress)))
	bodyBuffer.Write(TlvType0x188Encode([]byte(qqClient.Device.AndroidId)))
	bodyBuffer.Write(TlvType0x194Encode(qqClient.Device.ImsiHash))
	bodyBuffer.Write(TlvType0x191Encode(0x82))
	bodyBuffer.Write(TlvType0x202Encode([]byte(qqClient.Device.MacAddress), []byte(qqClient.Device.WIFISSID)))
	bodyBuffer.Write(TlvType0x177Encode(qqClient.Device.Protocol.BuildTime, qqClient.Device.Protocol.SdkVersion))
	bodyBuffer.Write(TlvType0x516Encode(0))
	bodyBuffer.Write(TlvType0x521Encode(0))
	bodyBuffer.Write(TlvType0x525Encode(TlvType0x536Encode([]byte{0x01, 0x00})))
	requestPack := qqClient.BuildRequestPack(qqClient.Uin, 2064, RequestEncryptEMECDH, bodyBuffer.Bytes())
	return qqClient.BuildNetworkPack(NetpackRequestTypeLogin, NetpackEncryptEmptyKey, seqence, qqClient.Uin, "wtlogin.login", requestPack), seqence
}

func (qqClient *QQClient) BuildLoginSliderSendPack(ticket string) ([]byte, uint16) {
	seqence := qqClient.NextSeqence()
	bodyBuffer := new(bytes.Buffer)
	bodyBuffer.Write(Int16ToBytes(2)) //subCommandId
	bodyBuffer.Write(Int16ToBytes(4)) //tlvNum
	bodyBuffer.Write(TlvType0x193Encode(ticket))
	bodyBuffer.Write(TlvType0x8Encode(2052))
	bodyBuffer.Write(TlvType0x104Encode(qqClient.Token.TlvType0x104Data))
	bodyBuffer.Write(TlvType0x116Encode(qqClient.Device.Protocol.Bitmap, qqClient.Device.Protocol.SubSigmap))
	requestPack := qqClient.BuildRequestPack(qqClient.Uin, 2064, RequestEncryptEMECDH, bodyBuffer.Bytes())
	return qqClient.BuildNetworkPack(NetpackRequestTypeLogin, NetpackEncryptEmptyKey, seqence, qqClient.Uin, "wtlogin.login", requestPack), seqence
}

func (qqClient *QQClient) BuildLoginSMSRequestPack() ([]byte, uint16) {
	seqence := qqClient.NextSeqence()
	bodyBuffer := new(bytes.Buffer)
	bodyBuffer.Write(Int16ToBytes(8)) //subCommandId
	bodyBuffer.Write(Int16ToBytes(6)) //tlvNum
	bodyBuffer.Write(TlvType0x8Encode(2052))
	bodyBuffer.Write(TlvType0x104Encode(qqClient.Token.TlvType0x104Data))
	bodyBuffer.Write(TlvType0x116Encode(qqClient.Device.Protocol.Bitmap, qqClient.Device.Protocol.SubSigmap))
	bodyBuffer.Write(TlvType0x174Encode(qqClient.Token.TlvType0x174Data))
	bodyBuffer.Write(TlvType0x17AEncode(9))
	bodyBuffer.Write(TlvType0x197Encode([]byte{0x00}))
	requestPack := qqClient.BuildRequestPack(qqClient.Uin, 2064, RequestEncryptEMECDH, bodyBuffer.Bytes())
	return qqClient.BuildNetworkPack(NetpackRequestTypeLogin, NetpackEncryptEmptyKey, seqence, qqClient.Uin, "wtlogin.login", requestPack), seqence
}

func (qqClient *QQClient) BuildLoginSMSSubmitPack(SMSCode string) ([]byte, uint16) {
	seqence := qqClient.NextSeqence()
	bodyBuffer := new(bytes.Buffer)
	bodyBuffer.Write(Int16ToBytes(7)) //subCommandId
	bodyBuffer.Write(Int16ToBytes(7)) //tlvNum
	bodyBuffer.Write(TlvType0x8Encode(2052))
	bodyBuffer.Write(TlvType0x104Encode(qqClient.Token.TlvType0x104Data))
	bodyBuffer.Write(TlvType0x116Encode(qqClient.Device.Protocol.Bitmap, qqClient.Device.Protocol.SubSigmap))
	bodyBuffer.Write(TlvType0x174Encode(qqClient.Token.TlvType0x174Data))
	bodyBuffer.Write(TlvType0x17CEncode(SMSCode))
	bodyBuffer.Write(TlvType0x401Encode(qqClient.Token.G))
	bodyBuffer.Write(TlvType0x198Encode())
	requestPack := qqClient.BuildRequestPack(qqClient.Uin, 2064, RequestEncryptEMECDH, bodyBuffer.Bytes())
	return qqClient.BuildNetworkPack(NetpackRequestTypeLogin, NetpackEncryptEmptyKey, seqence, qqClient.Uin, "wtlogin.login", requestPack), seqence
}

func (qqClient *QQClient) BuildLoginDeviceLockPack() ([]byte, uint16) {
	seqence := qqClient.NextSeqence()
	bodyBuffer := new(bytes.Buffer)
	bodyBuffer.Write(Int16ToBytes(20)) //subCommandId
	bodyBuffer.Write(Int16ToBytes(4))  //tlvNum
	bodyBuffer.Write(TlvType0x8Encode(2052))
	bodyBuffer.Write(TlvType0x104Encode(qqClient.Token.TlvType0x104Data))
	bodyBuffer.Write(TlvType0x116Encode(qqClient.Device.Protocol.Bitmap, qqClient.Device.Protocol.SubSigmap))
	bodyBuffer.Write(TlvType0x401Encode(qqClient.Token.G))
	requestPack := qqClient.BuildRequestPack(qqClient.Uin, 2064, RequestEncryptEMECDH, bodyBuffer.Bytes())
	return qqClient.BuildNetworkPack(NetpackRequestTypeLogin, NetpackEncryptEmptyKey, seqence, qqClient.Uin, "wtlogin.login", requestPack), seqence
}
