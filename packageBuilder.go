package FishBot

import (
	"bytes"
	"strconv"
	"time"

	"github.com/RomiChan/protobuf/proto"
	gojce "github.com/littlefish12345/go-jce"
	goqqjce "github.com/littlefish12345/go-qq-jce"
	goqqprotobuf "github.com/littlefish12345/go-qq-protobuf"
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
			headBuffer.Write(Int32ToBytes(int32(uint32(len(qqClient.Token.D2) + 4))))
			headBuffer.Write(qqClient.Token.D2)
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
		if len(qqClient.Token.Tgt) == 0 || len(qqClient.Token.Tgt) == 4 {
			bodyBuffer.Write([]byte{0x00, 0x00, 0x00, 0x04})
		} else {
			bodyBuffer.Write(Int32ToBytes(int32(uint32(len(qqClient.Token.Tgt) + 4))))
			bodyBuffer.Write(qqClient.Token.Tgt)
		}
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
		bodyEncoded = goqqtea.NewTeaCipher(qqClient.Token.D2Key).Encrypt(bodyEncoded)
	} else if encryptType == NetpackEncryptEmptyKey {
		bodyEncoded = goqqtea.NewTeaCipher(make([]byte, 16)).Encrypt(bodyEncoded)
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

func (qqClient *QQClient) BuildClientRegisterPack() ([]byte, uint16) {
	seqence := qqClient.NextSeqence()
	payloadStruct, _ := gojce.Marshal(goqqjce.ClientRegisterPackStruct{
		Uin:          qqClient.Uin,
		Bid:          7,
		ConnType:     0,
		Status:       11,
		KickPC:       false,
		KickWeak:     false,
		TimeStamp:    time.Now().Unix(),
		IOSVersion:   int64(qqClient.Device.Version.SDK),
		NetType:      1,
		RegType:      0,
		Guid:         qqClient.Device.Guid,
		LocaleId:     2052,
		DeviceName:   qqClient.Device.Model,
		DeviceType:   qqClient.Device.Model,
		OSVersion:    qqClient.Device.Version.Release,
		OpenPush:     true,
		LargeSeq:     0,
		VendorName:   qqClient.Device.VendorName,
		VendorOSName: qqClient.Device.VendorOSName,
		B769Request:  []byte{0x0A, 0x04, 0x08, 0x2E, 0x10, 0x00, 0x0A, 0x05, 0x08, 0x9B, 0x02, 0x10, 0x00},
		IsSetStatus:  false,
		SetMute:      false,
	})
	payloadData, _ := payloadStruct.ToBytes(0)
	requestStruct, _ := gojce.Marshal(goqqjce.RequestPacketStruct{
		Version:     3,
		ServantName: "PushService",
		FuncName:    "SvcReqRegister",
		Buffer:      gojce.JceSectionMapStrBytesToBytes(0, map[string][]byte{"SvcReqRegister": payloadData}),
	})
	requestData, _ := requestStruct.Encode()
	return qqClient.BuildNetworkPack(NetpackRequestTypeLogin, NetpackEncryptD2Key, seqence, qqClient.Uin, "StatSvc.register", requestData), seqence
}

func (qqClient *QQClient) BuildHeartBeatPack() ([]byte, uint16) {
	seqence := qqClient.NextSeqence()
	return qqClient.BuildNetworkPack(NetpackRequestTypeLogin, NetpackEncryptNoEncrypt, seqence, qqClient.Uin, "Heartbeat.Alive", []byte{}), seqence
}

func (qqClient *QQClient) BuildFriendListRequestPack(friendStartIndex uint16, friendListCount uint16, groupStartIndex uint8, groupListCount uint8) ([]byte, uint16) {
	seqence := qqClient.NextSeqence()
	D50RequestData, _ := proto.Marshal(goqqprotobuf.D50RequestStruct{
		AppId:                       1002,
		RequestMusicSwitch:          1,
		RequestMutualmarkAlienation: 1,
		RequestKsingSwitch:          1,
		RequestMutalmarkLbsShare:    1,
	})
	payloadStruct, _ := gojce.Marshal(goqqjce.FriendListRequest{
		RequestType:     3,
		IfReflush:       friendStartIndex > 0,
		Uin:             qqClient.Uin,
		StartIndex:      int16(friendStartIndex),
		FriendCount:     int16(friendListCount),
		GroupId:         1,
		IfGetGroupInfo:  groupStartIndex > 0,
		GroupStartIndex: byte(groupStartIndex),
		GroupCount:      groupListCount,
		IfGetMsfGroup:   false,
		IfShowTermType:  true,
		Version:         31,
		UinList:         nil,
		AppType:         0,
		IfGetDovId:      false,
		IfGetBothFlag:   false,
		D50Request:      D50RequestData,
		D6BRequest:      []byte{},
		SnsTypeList:     []int64{13580, 13581, 13582},
	})
	payloadData, _ := payloadStruct.ToBytes(0)
	requestStruct, _ := gojce.Marshal(goqqjce.RequestPacketStruct{
		Version:     3,
		ServantName: "mqq.IMService.FriendListServiceServantObj",
		FuncName:    "GetFriendListReq",
		Buffer:      gojce.JceSectionMapStrBytesToBytes(0, map[string][]byte{"FL": payloadData}),
	})
	requestData, _ := requestStruct.Encode()
	return qqClient.BuildNetworkPack(NetpackRequestTypeSimple, NetpackEncryptD2Key, seqence, qqClient.Uin, "friendlist.getFriendGroupList", requestData), seqence
}

func (qqClient *QQClient) BuildGroupListRequestPack(cookie []byte) ([]byte, uint16) {
	seqence := qqClient.NextSeqence()
	payloadStruct, _ := gojce.Marshal(goqqjce.TroopListRequestV2Simplify{
		Uin:               qqClient.Uin,
		GetMsfMessageFlag: true,
		Cookie:            cookie,
		GroupInfo:         []int64{},
		GroupFlagExt:      1,
		Version:           9,
		CompanyId:         0,
		VersionNumber:     1,
		GetLongGroupName:  true,
	})
	payloadData, _ := payloadStruct.ToBytes(0)
	requestStruct, _ := gojce.Marshal(goqqjce.RequestPacketStruct{
		Version:     3,
		ServantName: "mqq.IMService.FriendListServiceServantObj",
		FuncName:    "GetTroopListReqV2Simplify",
		Buffer:      gojce.JceSectionMapStrBytesToBytes(0, map[string][]byte{"GetTroopListReqV2Simplify": payloadData}),
	})
	requestData, _ := requestStruct.Encode()
	return qqClient.BuildNetworkPack(NetpackRequestTypeSimple, NetpackEncryptD2Key, seqence, qqClient.Uin, "friendlist.GetTroopListReqV2", requestData), seqence
}
