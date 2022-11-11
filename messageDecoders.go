package SakanaBot

import (
	goqqprotobuf "github.com/littlefish12345/go-qq-protobuf"
)

func DecodeRichTextElements(elements []*goqqprotobuf.Element) []*UniformRichTextElementStruct {
	var returnElements []*UniformRichTextElementStruct
	for _, element := range elements {
		if element.SourceMessage != nil && len(element.SourceMessage.OriginalSeqences) > 0 {
			returnElements = append(returnElements, &UniformRichTextElementStruct{
				RichTextElementType: RichTextElementTypeReply,
				ReplyElement: ReplyElementStruct{
					ReplySeqence: element.SourceMessage.OriginalSeqences[0],
					Time:         element.SourceMessage.GetTime(),
					SenderUin:    element.SourceMessage.GetSenderUin(),
					TargetUin:    element.SourceMessage.GetToUin(),
					Elements:     DecodeRichTextElements(element.SourceMessage.Element),
				},
			})
		}
		if element.Text != nil {
			if len(element.Text.Attribute6Buffer) > 0 {
				if element.Text.Attribute6Buffer[6] != 0x00 {
					returnElements = append(returnElements, &UniformRichTextElementStruct{
						RichTextElementType: RichTextElementTypeAtAll,
					})
				} else {
					returnElements = append(returnElements, &UniformRichTextElementStruct{
						RichTextElementType: RichTextElementTypeAt,
						AtElement: AtElementStruct{
							TargetUin: int64(uint32(BytesToInt32(element.Text.Attribute6Buffer[7:11]))),
							Display:   element.Text.GetString_(),
						},
					})
				}
			} else {
				returnElements = append(returnElements, &UniformRichTextElementStruct{
					RichTextElementType: RichTextElementTypeText,
					TextElement: TextElementStruct{
						Text: element.Text.GetString_(),
					},
				})
			}
		}
		if element.NotOnlineImage != nil {
			var imageUrl string
			if element.NotOnlineImage.GetOriginalUrl() != "" {
				imageUrl = "https://c2cpicdw.qpic.cn" + element.NotOnlineImage.GetOriginalUrl()
			} else {
				downloadPath := element.NotOnlineImage.GetResId()
				if *element.NotOnlineImage.DownloadPath != "" {
					downloadPath = element.NotOnlineImage.GetDownloadPath()
				}
				if downloadPath[0] != '/' {
					downloadPath = "/" + downloadPath
				}
				imageUrl = "https://c2cpicdw.qpic.cn/offpic_new/0" + downloadPath + "/0?term=3"
			}
			returnElements = append(returnElements, &UniformRichTextElementStruct{
				RichTextElementType: RichTextElementTypeOfflineImage,
				OfflineImageElement: OfflineImageElementStruct{
					ImageId:   element.NotOnlineImage.GetFilePath(),
					ImageSize: element.NotOnlineImage.GetFileLength(),
					ImageUrl:  imageUrl,
					Md5:       element.NotOnlineImage.GetPictureMd5(),
				},
			})
		}
	}
	return returnElements
}

func (qqClient *QQClient) PrivateMessageDecoder(pairMessage *goqqprotobuf.Message) *UniformMessageStruct {
	isFriend, senderNickname := qqClient.FindFriend(*pairMessage.MessageHead.FromUin)
	if !isFriend {
		senderNickname = *pairMessage.MessageHead.FromNickname
	}
	if pairMessage.MessageBody.RichText == nil || pairMessage.MessageBody.RichText.Element == nil {
		return nil
	}
	returnUniformMessage := &UniformMessageStruct{
		MessageSeqence: *pairMessage.MessageHead.MessageSeqence,
		Time:           *pairMessage.MessageHead.MessageTime,
		TargetUin:      *pairMessage.MessageHead.ToUin,
		SenderUin:      *pairMessage.MessageHead.FromUin,
		SenderNickname: senderNickname,
		SenderIsFriend: isFriend,
		SelfUin:        qqClient.Uin,
	}

	if pairMessage.MessageBody.RichText.Ptt != nil {
		returnUniformMessage.MessageType = MessageTypeVoice
		returnUniformMessage.VoiceMessage = VoiceMessageStruct{
			Name: pairMessage.MessageBody.RichText.Ptt.GetFileName(),
			Md5:  pairMessage.MessageBody.RichText.Ptt.GetFileMd5(),
			Size: pairMessage.MessageBody.RichText.Ptt.GetFileSize(),
			Url:  string(pairMessage.MessageBody.RichText.Ptt.GetDownPara()),
		}
	} else {
		returnUniformMessage.MessageType = MessageTypeRichText
		returnUniformMessage.RichTextMessage = DecodeRichTextElements(pairMessage.MessageBody.RichText.Element)
	}

	return returnUniformMessage
}
