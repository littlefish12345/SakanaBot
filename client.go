package SakanaBot

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	goqqjce "github.com/littlefish12345/go-qq-jce"
)

type QQClient struct {
	Uin                        int64
	PaswordHash                [16]byte
	Device                     *DeviceInfo
	SsoServerList              []goqqjce.SsoServerInfoStruct
	ResponsePackLock           sync.Mutex
	ResponsePackNotHandledMap  map[uint16]*NetworkPackStruct
	ResponsePackWaitChannelMap map[uint16]chan *NetworkPackStruct

	Connected         bool
	Conn              net.Conn
	PackageSequenceId *SafeInt32
	FriendSeqenceId   *SafeInt32
	SessionId         []byte
	Ksid              []byte

	Token              *Token
	WtSessionTicketKey []byte

	ECDHKey   *ECDHKey
	RandomKey []byte

	Age      byte
	Sex      byte
	NickName string

	FriendList []*goqqjce.FriendInfoStruct

	IsInit              bool
	SyncCookie          []byte
	PublicAccountCookie []byte

	Online bool
}

func NewClient(uin int64, paswordHash [16]byte, device *DeviceInfo) (*QQClient, error) {
	qqClient := QQClient{}
	qqClient.Uin = uin
	qqClient.PaswordHash = paswordHash
	qqClient.Device = device
	var err error
	qqClient.SsoServerList, err = getSsoServerList(device.Protocol.AppId, device.IMEI)
	qqClient.ResponsePackNotHandledMap = make(map[uint16]*NetworkPackStruct)
	qqClient.ResponsePackWaitChannelMap = map[uint16]chan *NetworkPackStruct{}

	qqClient.Connected = false
	qqClient.PackageSequenceId = new(SafeInt32)
	qqClient.PackageSequenceId.Set(0x3635)
	qqClient.FriendSeqenceId = new(SafeInt32)
	qqClient.FriendSeqenceId.Set(22911)
	qqClient.SessionId = []byte{0x02, 0xB0, 0x5B, 0x8B}
	qqClient.Ksid = []byte("|" + device.IMEI + "|A8.2.7.27f6ea96")

	qqClient.Token = new(Token)

	qqClient.ECDHKey = NewECDHKey()
	qqClient.ECDHKey.GetPublicKey(qqClient.Uin)
	qqClient.RandomKey = make([]byte, 16)
	rand.Read(qqClient.RandomKey)
	return &qqClient, err
}

func (qqClient *QQClient) NextSeqence() uint16 {
	return uint16(qqClient.PackageSequenceId.Add(1) & 0x7FFF)
}

func (qqClient *QQClient) ClientRegister() error {
	netpack := qqClient.RecvPack(qqClient.SendPack(qqClient.BuildClientRegisterPack()))
	return qqClient.DecodeRegisterResponse(netpack.Body)
}

func (qqClient *QQClient) Init() error {
	qqClient.IsInit = true
	err := qqClient.ClientRegister()
	if err != nil {
		return err
	}
	qqClient.Online = true
	go qqClient.HeartBeat()
	qqClient.FriendList = qqClient.GetFriendList()
	qqClient.GetMessage(GetMessageSyncFlagStart)
	qqClient.IsInit = false
	return nil
}

func (qqClient *QQClient) HeartBeat() {
	count := 0
	for qqClient.Connected && qqClient.Online {
		time.Sleep(time.Second * 30)
		_ = qqClient.RecvPack(qqClient.SendPack(qqClient.BuildHeartBeatPack()))
		if count == 7 {
			qqClient.ClientRegister()
			count = 0
		}
		count++
	}
}

func (qqClient *QQClient) GetFriendList() []*goqqjce.FriendInfoStruct {
	var totalFriendCount uint16
	var allFriendInfoList []*goqqjce.FriendInfoStruct
	var friendInfoList []*goqqjce.FriendInfoStruct
	for {
		netpack := qqClient.RecvPack(qqClient.SendPack(qqClient.BuildFriendListRequestPack(uint16(len(allFriendInfoList)), 150, 0, 0)))
		totalFriendCount, friendInfoList = qqClient.DecodeFriendGroupListResponse(netpack.Body)
		allFriendInfoList = append(allFriendInfoList, friendInfoList...)
		if len(allFriendInfoList) >= int(totalFriendCount) {
			break
		}
	}
	return allFriendInfoList
}

func (qqClient *QQClient) GetGroupList() []*goqqjce.TroopNumStruct {
	var cookie []byte
	var allTroopNumList []*goqqjce.TroopNumStruct
	var troopNumList []*goqqjce.TroopNumStruct
	for {
		netpack := qqClient.RecvPack(qqClient.SendPack(qqClient.BuildGroupListRequestPack(cookie)))
		troopNumList, cookie = qqClient.DecodeGroupListResponse(netpack.Body)
		allTroopNumList = append(allTroopNumList, troopNumList...)
		if len(cookie) == 0 {
			break
		}
	}
	return allTroopNumList
}

func (qqClient *QQClient) GetMessage(syncFlag uint32) {
	netpack := qqClient.RecvPack(qqClient.SendPack(qqClient.BuildGetMessageRequestPack(syncFlag)))
	fmt.Println(netpack)
	qqClient.DecodeGetMessageRequestPack(netpack.Body)
}
