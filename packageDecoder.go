package FishBot

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strconv"
	"time"

	gojce "github.com/littlefish12345/go-jce"
	goqqjce "github.com/littlefish12345/go-qq-jce"
	goqqtea "github.com/littlefish12345/go-qq-tea"
)

type NetworkPackStruct struct {
	ResponseType uint32
	EncryptType  byte
	Uin          int64
	Seqence      uint16
	ReturnCode   int32
	Message      string
	CommandName  string
	SessionId    []byte
	Body         []byte
}

func (qqClient *QQClient) DecodeNetworkPack(data []byte) (*NetworkPackStruct, error) { //responseType encryptType uin seqence returnCode message commandName body
	responseType := BytesToInt32(data[0:4])
	encryptType := data[4]
	uinLenght := BytesToInt32(data[6:10]) - 4
	uin, _ := strconv.ParseInt(string(data[10:10+uinLenght]), 10, 64)
	packBody := data[10+uinLenght:]
	if encryptType == NetpackEncryptD2Key {
		packBody = goqqtea.NewTeaCipher(qqClient.Token.D2Key).Decrypt(packBody)
	} else if encryptType == NetpackEncryptEmptyKey {
		packBody = goqqtea.NewTeaCipher(make([]byte, 16)).Decrypt(packBody)
	}

	headLength := BytesToInt32(packBody[0:4]) - 4
	if headLength < 0 || headLength > int32(len(packBody)) {
		return nil, ErrorPackLengthError
	}
	head := packBody[4 : 4+headLength]
	seqence := BytesToInt32(head[0:4])
	returnCode := BytesToInt32(head[4:8])
	messageLength := BytesToInt32(head[8:12]) - 4
	message := string(head[12 : 12+messageLength])
	commandNameLength := BytesToInt32(head[12+messageLength:16+messageLength]) - 4
	commandName := string(head[16+messageLength : 16+messageLength+commandNameLength])
	sessionIdLength := BytesToInt32(head[16+messageLength+commandNameLength:20+messageLength+commandNameLength]) - 4
	sessionId := head[20+messageLength+commandNameLength : 20+messageLength+commandNameLength+sessionIdLength]
	compressedFlag := BytesToInt32(head[20+messageLength+commandNameLength+sessionIdLength : 24+messageLength+commandNameLength+sessionIdLength])
	bodyLenght := BytesToInt32(packBody[4+headLength:8+headLength]) - 4
	body := packBody[8+headLength:]
	if bodyLenght > 0 && bodyLenght < int32(len(body)) {
		body = body[:bodyLenght]
	}
	if compressedFlag == 1 {
		bodyCompressReader, _ := zlib.NewReader(bytes.NewReader(body))
		body, _ = ioutil.ReadAll(bodyCompressReader)
		bodyCompressReader.Close()
	}
	return &NetworkPackStruct{
		ResponseType: uint32(responseType),
		EncryptType:  encryptType,
		Uin:          uin,
		Seqence:      uint16(seqence),
		ReturnCode:   returnCode,
		Message:      message,
		CommandName:  commandName,
		SessionId:    sessionId,
		Body:         body,
	}, nil
}

func (qqClient *QQClient) DecodeResponsePack(data []byte) (uint16, int64, []byte) { //command uin body
	flag := data[0]
	if flag != 2 {
		return 0, 0, nil
	}
	command := BytesToInt16(data[5:7])
	uin := int64(BytesToInt32(data[9:13]))
	encryptType := data[14]
	body := data[16 : len(data)-1]
	if encryptType == 0 {
		body = goqqtea.NewTeaCipher(qqClient.ECDHKey.ShareKey).Decrypt(body)
	}
	return uint16(command), uin, body
}

func (qqClient *QQClient) DecodeLoginResponseNetworkPack(netpackStruct *NetworkPackStruct) *LoginResponse {
	_, _, responsePackBody := qqClient.DecodeResponsePack(netpackStruct.Body)
	return qqClient.DecodeLoginResponse(responsePackBody)
}

func (qqClient *QQClient) DecodeLoginResponse(data []byte) *LoginResponse {
	//subCommand := BytesToInt16(data[0:2])
	status := data[2]
	tlvMap := TlvRead(data[5:], 2)

	if tlvType0x402Data, ok := tlvMap[0x402]; ok {
		str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		bytes := []byte(str)
		qqClient.Token.Dpwd = []byte{}
		rand.Seed(time.Now().UnixNano() + int64(rand.Intn(100)))
		for i := 0; i < 16; i++ {
			qqClient.Token.Dpwd = append(qqClient.Token.Dpwd, bytes[rand.Intn(len(bytes))])
		}
		qqClient.Token.TlvType0x402Data = tlvType0x402Data
		hash := md5.Sum(append(qqClient.Device.Guid, append(qqClient.Token.Dpwd, qqClient.Token.TlvType0x402Data...)...))
		qqClient.Token.G = hash[:]
	}

	if status == 0 {
		if TlvType0x403Data, ok := tlvMap[0x403]; ok {
			qqClient.Token.RansSeed = TlvType0x403Data
		}
		qqClient.DecodeLoginResponseSuccessTlv(tlvMap[0x119])
		return &LoginResponse{
			Success: true,
		}
	}

	if status == 2 {
		qqClient.Token.TlvType0x104Data = tlvMap[0x104]
		if type0x192Data, ok := tlvMap[0x192]; ok {
			return &LoginResponse{
				Success:         false,
				Error:           LoginResponseNeedSlider,
				SliderVerifyUrl: string(type0x192Data),
			}
		}
	}

	if status == 160 || status == 239 {
		if tlvType0x174Data, ok := tlvMap[0x174]; ok {
			qqClient.Token.TlvType0x104Data = tlvMap[0x104]
			qqClient.Token.TlvType0x174Data = tlvType0x174Data
			qqClient.Token.RansSeed = tlvMap[0x403]
			phoneNum := string(tlvMap[0x178][2 : 2+BytesToInt16(tlvMap[0x178][0:2])])
			return &LoginResponse{
				Success:     false,
				Error:       LoginResponseNeedSMS,
				SMSPhoneNum: phoneNum,
			}
		}

		if _, ok := tlvMap[0x17B]; ok {
			return &LoginResponse{
				Success: false,
				Error:   LoginResponseNeedSMS,
			}
		}
	}

	if status == 204 {
		qqClient.Token.TlvType0x104Data = tlvMap[0x104]
		qqClient.Token.RansSeed = tlvMap[0x403]
		netpack := qqClient.RecvPack(qqClient.SendPack(qqClient.BuildLoginDeviceLockPack()))
		return qqClient.DecodeLoginResponseNetworkPack(netpack)
	}

	if tlvType0x146Data, ok := tlvMap[0x146]; ok {
		pointer := 4
		titleLength := uint16(BytesToInt16(tlvType0x146Data[pointer : pointer+2]))
		pointer += 2
		//title := string(tlvType0x146Data[pointer : pointer+int(titleLength)])
		pointer += int(titleLength)
		messageLength := uint16(BytesToInt16(tlvType0x146Data[pointer : pointer+2]))
		pointer += 2
		message := string(tlvType0x146Data[pointer : pointer+int(messageLength)])
		return &LoginResponse{
			Success: false,
			Error:   LoginResponseOtherError,
			Message: message,
		}
	}
	return &LoginResponse{}
}

func (qqClient *QQClient) DecodeRegisterResponse(data []byte) error {
	requestStruct := &goqqjce.RequestPacketStruct{}
	gojce.Unmarshal(data, requestStruct)
	payloadMap := gojce.JceSectionMapStrMapStrBytesFromBytes(gojce.NewJceReader(requestStruct.Buffer))
	payloadStruct := &goqqjce.ClientRegisterResponsePackStruct{}
	gojce.Unmarshal(payloadMap["SvcRespRegister"]["QQService.SvcRespRegister"][1:], payloadStruct)
	if payloadStruct.Result != "" {
		return errors.New("client register failed: " + payloadStruct.Result)
	}
	if payloadStruct.ReplyCode != 0 {
		return errors.New("client register failed: replyCode: " + strconv.Itoa(int(payloadStruct.ReplyCode)))
	}
	return nil
}

func (qqClient *QQClient) DecodeFriendGroupListResponse(data []byte) (uint16, []*goqqjce.FriendInfoStruct) {
	requestStruct := &goqqjce.RequestPacketStruct{}
	gojce.Unmarshal(data, requestStruct)
	payloadMap := gojce.JceSectionMapStrBytesFromBytes(gojce.NewJceReader(requestStruct.Buffer))
	reader := gojce.NewJceReader(payloadMap["FLRESP"][1:])
	reader.SkipToId(5)
	friendNum := uint16(gojce.JceSectionInt16FromBytes(reader))
	reader.SkipToId(7)
	reader.SkipHead()
	friendListLength := uint32(gojce.JceSectionInt32FromBytes(reader))
	var returnFriendInfoList []*goqqjce.FriendInfoStruct
	var friendInfo *goqqjce.FriendInfoStruct
	var structData []byte
	for i := 0; i < int(friendListLength); i++ {
		friendInfo = new(goqqjce.FriendInfoStruct)
		structData, _ = reader.ReadJceStructByte()
		err := gojce.Unmarshal(structData, friendInfo)
		if err != nil {
			fmt.Println(err)
		}
		returnFriendInfoList = append(returnFriendInfoList, friendInfo)
	}
	return friendNum, returnFriendInfoList
}

func (qqClient *QQClient) DecodeGroupListResponse(data []byte) ([]*goqqjce.TroopNumStruct, []byte) {
	requestStruct := &goqqjce.RequestPacketStruct{}
	gojce.Unmarshal(data, requestStruct)
	payloadMap := gojce.JceSectionMapStrBytesFromBytes(gojce.NewJceReader(requestStruct.Buffer))
	payload := payloadMap["GetTroopListRespV2"][1:]
	reader := gojce.NewJceReader(payload)
	reader.SkipToId(4)
	cookie := gojce.JceSectionBytesFromBytes(reader)
	reader.SkipToId(5)
	reader.SkipHead()
	troopNumListLength := uint32(gojce.JceSectionInt32FromBytes(reader))
	var returnTroopNumList []*goqqjce.TroopNumStruct
	var troopNum *goqqjce.TroopNumStruct
	var structData []byte
	for i := 0; i < int(troopNumListLength); i++ {
		troopNum = new(goqqjce.TroopNumStruct)
		structData, _ = reader.ReadJceStructByte()
		err := gojce.Unmarshal(structData, troopNum)
		if err != nil {
			fmt.Println(err)
		}
		returnTroopNumList = append(returnTroopNumList, troopNum)
	}
	return returnTroopNumList, cookie
}
