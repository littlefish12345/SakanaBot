package SakanaBot

import (
	"fmt"

	goqqprotobuf "github.com/littlefish12345/go-qq-protobuf"
)

func (qqClient *QQClient) ProcessMessage(pairMessage *goqqprotobuf.Message) *UniformMessageStruct {
	//if qqClient.IsInit {
	//	return nil
	//}
	fmt.Println(*pairMessage.MessageHead.MessageType)
	switch *pairMessage.MessageHead.MessageType {
	case 9, 10, 31, 79, 97, 120, 132, 133, 166, 167:
		if *pairMessage.MessageHead.C2CCmd == 11 || *pairMessage.MessageHead.C2CCmd == 175 {
			return qqClient.PrivateMessageDecoder(pairMessage)
		}
	case 208:
		return qqClient.PrivateMessageDecoder(pairMessage)
	case 35, 36, 37, 45, 46, 84, 85, 86, 87:

	}
	return nil
}

func (qqClient *QQClient) SyncMessage(responseStruct *goqqprotobuf.GetMessageResponseStruct) {
	if *responseStruct.MessageResponseType == 0 {
		qqClient.SyncCookie = responseStruct.SyncCookie
		qqClient.PublicAccountCookie = responseStruct.PublicAccountCookie
	} else if *responseStruct.MessageResponseType == 1 {
		qqClient.SyncCookie = responseStruct.SyncCookie
	} else if *responseStruct.MessageResponseType == 2 {
		qqClient.PublicAccountCookie = responseStruct.PublicAccountCookie
	}
	if responseStruct.UinPairMessages == nil {
		return
	}

	var deleteMessageList []*goqqprotobuf.MessageItem
	for _, uinPairMessage := range responseStruct.UinPairMessages {
		for _, pairMessage := range uinPairMessage.Message {
			deleteMessageItem := &goqqprotobuf.MessageItem{
				FromUin:        pairMessage.MessageHead.FromUin,
				ToUin:          pairMessage.MessageHead.ToUin,
				MessageType:    pairMessage.MessageHead.MessageType,
				MessageSeqence: pairMessage.MessageHead.MessageSeqence,
				MessageUid:     pairMessage.MessageHead.MessageUid,
			}
			deleteMessageList = append(deleteMessageList, deleteMessageItem)
			if (int64(*uinPairMessage.LastReadTime) & 0xFFFFFFFF) > int64(*pairMessage.MessageHead.MessageTime) {
				continue
			}
			uniformMessage := qqClient.ProcessMessage(pairMessage)

			if uniformMessage != nil {
				fmt.Println(uniformMessage.SenderIsFriend, uniformMessage.SenderNickname, uniformMessage.SenderUin)
				if uniformMessage.MessageType == MessageTypeVoice {
					fmt.Println(uniformMessage.VoiceMessage)
				} else if uniformMessage.MessageType == MessageTypeRichText {
					for _, element := range uniformMessage.RichTextMessage {
						fmt.Println(element)
						if element.RichTextElementType == RichTextElementTypeReply {
							for _, elem := range element.ReplyElement.Elements {
								fmt.Println(elem)
							}
						}
					}
				}
				fmt.Println()
			}
		}
	}
	if deleteMessageList != nil {
		qqClient.RecvPack(qqClient.SendPack(qqClient.BuildDeleteMessageRequestPack(deleteMessageList)))
	}
	if *responseStruct.SyncFlag != MessageSyncFlagStop {
		qqClient.GetMessage(*responseStruct.SyncFlag)
	}
}
