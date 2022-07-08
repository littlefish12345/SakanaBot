package FishBot

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"time"

	goqqtea "github.com/littlefish12345/go-qq-tea"
)

const (
	LoginMethodPassword uint16 = 0
)

func (qqClient *QQClient) Login(method uint16) *LoginResponse {
	if !qqClient.Connected {
		qqClient.Connect()
	}
	if method == LoginMethodPassword {
		netpack := qqClient.RecvPack(qqClient.SendPack(qqClient.BuildLoginPack()))
		return qqClient.DecodeLoginResponseNetworkPack(netpack)
	}
	return nil
}

func (qqClient *QQClient) RequestSMSCode() bool {
	if !qqClient.Connected {
		qqClient.Connect()
	}
	netpack := qqClient.RecvPack(qqClient.SendPack(qqClient.BuildLoginSMSRequestPack()))
	return qqClient.DecodeLoginResponseNetworkPack(netpack).Error == LoginResponseNeedSMS
}

func (qqClient *QQClient) SubmitSMSCode(SMSCode string) *LoginResponse {
	if !qqClient.Connected {
		qqClient.Connect()
	}
	netpack := qqClient.RecvPack(qqClient.SendPack(qqClient.BuildLoginSMSSubmitPack(SMSCode)))
	return qqClient.DecodeLoginResponseNetworkPack(netpack)
}

func (qqClient *QQClient) DecodeLoginResponseSuccessTlv(payload []byte) {
	data := goqqtea.NewTeaCipher(qqClient.Device.TgtgtKey).Decrypt(payload)
	tlvMap := TlvRead(data[2:], 2)
	fmt.Println(tlvMap)
	if TlvType0x108Data, ok := tlvMap[0x108]; ok {
		qqClient.Ksid = TlvType0x108Data
	}

	if TlvType0x11AData, ok := tlvMap[0x11A]; ok {
		qqClient.Age = TlvType0x11AData[2]
		qqClient.Sex = TlvType0x11AData[3]
		qqClient.NickName = string(TlvType0x11AData[5 : 5+TlvType0x11AData[4]])
	}

	if TlvType0x512Data, ok := tlvMap[0x512]; ok {
		qqClient.Token.PsKeyMap = make(map[string][]byte)
		qqClient.Token.Pt4TokenMap = make(map[string][]byte)
		length := uint16(BytesToInt16(TlvType0x512Data[0:2]))
		pointer := 2
		var partLength uint16
		var domain string
		var psKey []byte
		var pt4Token []byte
		for i := 0; i < int(length); i++ {
			partLength = uint16(BytesToInt16(TlvType0x512Data[pointer : pointer+2]))
			pointer += 2
			domain = string(TlvType0x512Data[pointer : pointer+int(partLength)])
			pointer += int(partLength)
			partLength = uint16(BytesToInt16(TlvType0x512Data[pointer : pointer+2]))
			pointer += 2
			psKey = TlvType0x512Data[pointer : pointer+int(partLength)]
			pointer += int(partLength)
			partLength = uint16(BytesToInt16(TlvType0x512Data[pointer : pointer+2]))
			pointer += 2
			pt4Token = TlvType0x512Data[pointer : pointer+int(partLength)]
			pointer += int(partLength)

			if len(psKey) > 0 {
				qqClient.Token.PsKeyMap[domain] = psKey
			}
			if len(pt4Token) > 0 {
				qqClient.Token.Pt4TokenMap[domain] = pt4Token
			}
		}
	}

	if TlvType0x134Data, ok := tlvMap[0x134]; ok {
		qqClient.WtSessionTicketKey = TlvType0x134Data
	}
	if TlvType0x16AData, ok := tlvMap[0x16A]; ok {
		qqClient.Token.SrmToken = TlvType0x16AData
	}
	if TlvType0x16AData, ok := tlvMap[0x16A]; ok {
		qqClient.Token.SrmToken = TlvType0x16AData
	}
	if TlvType0x133Data, ok := tlvMap[0x133]; ok {
		qqClient.Token.TlvType0x133Data = TlvType0x133Data
	}
	qqClient.Token.Tgt = tlvMap[0x10A]
	qqClient.Token.TgtKey = tlvMap[0x10D]
	qqClient.Token.UserSTKey = tlvMap[0x10E]
	qqClient.Token.UserSTWebSig = tlvMap[0x103]
	qqClient.Token.SKey = tlvMap[0x120]
	qqClient.Token.SKeyExpiredTime = time.Now().Unix() + 21600
	qqClient.Token.D2 = tlvMap[0x143]
	qqClient.Token.D2Key = tlvMap[0x305]
	qqClient.Token.DeviceToken = tlvMap[0x322]

	keyBody := new(bytes.Buffer)
	keyBody.Write(qqClient.PaswordHash[:])
	keyBody.Write([]byte{0x00, 0x00, 0x00, 0x00})
	keyBody.Write(Int32ToBytes(int32(uint32(qqClient.Uin))))
	key := md5.Sum(keyBody.Bytes())
	if TlvType0x106Data, ok := tlvMap[0x106]; ok {
		decryptedA1 := goqqtea.NewTeaCipher(key[:]).Decrypt(TlvType0x106Data)
		if len(decryptedA1) > 51+16 {
			qqClient.Device.TgtgtKey = decryptedA1[51 : 51+16]
		}
	}
}
