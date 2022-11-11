package SakanaBot

const (
	MessageSyncFlagStart    uint32 = 0x00
	MessageSyncFlagContinue uint32 = 0x01
	MessageSyncFlagStop     uint32 = 0x02
)

const (
	MessageTypeVoice    uint16 = 0x01
	MessageTypeRichText uint16 = 0x02
)

const (
	RichTextElementTypeReply        uint16 = 0x01
	RichTextElementTypeAtAll        uint16 = 0x02
	RichTextElementTypeAt           uint16 = 0x03
	RichTextElementTypeText         uint16 = 0x03
	RichTextElementTypeOfflineImage uint16 = 0x04
)

type ReplyElementStruct struct {
	ReplySeqence uint32
	Time         uint32
	SenderUin    int64
	TargetUin    int64
	Elements     []*UniformRichTextElementStruct
}

type AtElementStruct struct {
	TargetUin int64
	Display   string
}

type TextElementStruct struct {
	Text string
}

type OfflineImageElementStruct struct {
	ImageId   string
	ImageSize uint32
	ImageUrl  string
	Md5       []byte
}

type UniformRichTextElementStruct struct {
	RichTextElementType uint16
	ReplyElement        ReplyElementStruct
	AtElement           AtElementStruct
	TextElement         TextElementStruct
	OfflineImageElement OfflineImageElementStruct
}

type VoiceMessageStruct struct {
	Name string
	Md5  []byte
	Size uint32
	Url  string
}

type UniformMessageStruct struct {
	MessageType     uint16
	MessageSeqence  uint32
	Time            uint32
	TargetUin       int64
	SenderUin       int64
	SenderNickname  string
	SenderIsFriend  bool
	SelfUin         int64
	VoiceMessage    VoiceMessageStruct
	RichTextMessage []*UniformRichTextElementStruct
}
