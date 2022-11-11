package SakanaBot

import (
	"fmt"

	gojce "github.com/littlefish12345/go-jce"
	goqqjce "github.com/littlefish12345/go-qq-jce"
)

func (qqClient *QQClient) HandleConfigPushRequest(data []byte) {
	requestStruct := &goqqjce.RequestPacketStruct{}
	gojce.Unmarshal(data, requestStruct)
	payloadMap := gojce.JceSectionMapStrMapStrBytesFromBytes(gojce.NewJceReader(requestStruct.Buffer))
	reader := gojce.NewJceReader(payloadMap["PushReq"]["ConfigPush.PushReq"][1:])
	reader.SkipToId(1)
	configType := gojce.JceSectionInt32FromBytes(reader)
	configBytes := gojce.JceSectionBytesFromBytes(reader)
	/*
		if len(configBytes) > 0 {
			if configType == 1 {
				ssoServerInfoReader := gojce.NewJceReader(configBytes)
				ssoServerInfoList, err := decodeSsoServerInfo(gojce.NewJceReader(ssoServerInfoReader))
				if err != nil {
					return nil, err
				}
			}
		}
	*/
	configSeqence := gojce.JceSectionInt64FromBytes(reader)
	fmt.Println("config push done", configType)
	qqClient.SendPack(qqClient.BuildConfigPushResponsePack(configType, configBytes, configSeqence))
}

func (qqClient *QQClient) HandleOnlinePushRequest(netpack *NetworkPackStruct) {
	requestStruct := &goqqjce.RequestPacketStruct{}
	gojce.Unmarshal(netpack.Body, requestStruct)
	payloadMap := gojce.JceSectionMapStrMapStrBytesFromBytes(gojce.NewJceReader(requestStruct.Buffer))
	reader := gojce.NewJceReader(payloadMap["req"]["OnlinePushPack.SvcReqPushMsg"][1:])
	uin := gojce.JceSectionInt64FromBytes(reader)
	reader.SkipToId(2)
	reader.SkipHead()
	onlinePushMessageInfoLength := uint32(gojce.JceSectionInt32FromBytes(reader))
	var onlinePushMessageInfoList []*goqqjce.OnlinePushMessageInfoStruct
	var onlinePushMessageInfo *goqqjce.OnlinePushMessageInfoStruct
	var structData []byte
	for i := 0; i < int(onlinePushMessageInfoLength); i++ {
		onlinePushMessageInfo = new(goqqjce.OnlinePushMessageInfoStruct)
		structData, _ = reader.ReadJceStructByte()
		err := gojce.Unmarshal(structData, onlinePushMessageInfo)
		if err != nil {
			fmt.Println(err)
		}
		onlinePushMessageInfoList = append(onlinePushMessageInfoList, onlinePushMessageInfo)
	}
	qqClient.SendPack(qqClient.BuildOnlinePushMessageRequestPack(uin, netpack.Seqence, 0, []byte{}, onlinePushMessageInfoList))

	for _, messageInfo := range onlinePushMessageInfoList {
		fmt.Println(messageInfo.MessageType)
		if messageInfo.MessageType == 0x210 {
			vecMessageReader := gojce.NewJceReader(messageInfo.VecMessage)
			messageSubType := gojce.JceSectionInt64FromBytes(vecMessageReader)
			fmt.Println(messageSubType)
		}
	}
}

func (qqClient *QQClient) HandlePushNotifyRequest(netpack *NetworkPackStruct) {
	requestStruct := &goqqjce.RequestPacketStruct{}
	gojce.Unmarshal(netpack.Body, requestStruct)
	payloadMap := gojce.JceSectionMapStrMapStrBytesFromBytes(gojce.NewJceReader(requestStruct.Buffer))
	if len(payloadMap) == 0 {
		qqClient.GetMessage(GetMessageSyncFlagStart)
		return
	}
	payloadStruct := &goqqjce.PushNotifyStruct{}
	gojce.Unmarshal(payloadMap["req_PushNotify"]["PushNotifyPack.RequestPushNotify"][1:], payloadStruct)
	fmt.Println(payloadStruct.MessageType)
	qqClient.SyncCookie = payloadStruct.NotifyCookie
	qqClient.GetMessage(GetMessageSyncFlagStart)
}
