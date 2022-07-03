package FishBot

import (
	"fmt"
	"math/rand"
	"net"
)

type QQClient struct {
	Uin           int64
	PaswordHash   [16]byte
	Device        *DeviceInfo
	SsoServerList []SsoServerInfoStruct

	Connected         bool
	Conn              net.Conn
	PackageSequenceId *SafeInt32
	SessionId         []byte
	Ksid              []byte

	ECDHKey   *ECDHKey
	RandomKey []byte
}

func NewClient(uin int64, paswordHash [16]byte, device *DeviceInfo) (*QQClient, error) {
	qqClient := QQClient{}
	qqClient.Uin = uin
	qqClient.PaswordHash = paswordHash
	qqClient.Device = device
	var err error
	qqClient.SsoServerList, err = getSsoServerList(device.Protocol.AppId, device.IMEI)
	qqClient.Connected = false
	qqClient.PackageSequenceId = new(SafeInt32)
	qqClient.PackageSequenceId.Set(0x3635)
	qqClient.SessionId = []byte{0x02, 0xB0, 0x5B, 0x8B}
	qqClient.Ksid = []byte("|" + device.IMEI + "|A8.2.7.27f6ea96")

	qqClient.ECDHKey = NewECDHKey()
	qqClient.ECDHKey.GetPublicKey(qqClient.Uin)
	qqClient.RandomKey = make([]byte, 16)
	rand.Read(qqClient.RandomKey)
	return &qqClient, err
}

func (qqClient *QQClient) NextSeqence() uint16 {
	return uint16(qqClient.PackageSequenceId.Add(1) & 0x7FFF)
}

func (qqClient *QQClient) Login() {
	if !qqClient.Connected {
		qqClient.connect()
	}
	qqClient.SendPack(qqClient.BuildLoginPack())
	netpack, _ := qqClient.RecvPack()
	responseType, encryptType, uin, seqence, returnCode, message, commandName, body, _ := qqClient.DecodeNetworkPack(netpack)
	fmt.Println(responseType, encryptType, uin, seqence, returnCode, message, commandName, body)
	command, uin, responsePackBody := qqClient.DecodeResponsePack(body)
	fmt.Println(command, uin)
	fmt.Println(responsePackBody)
}
