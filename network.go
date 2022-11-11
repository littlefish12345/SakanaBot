package SakanaBot

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

var (
	ErrorNoServerIsReachable = errors.New("error: No server is reachable")
	ErrorPackLengthError     = errors.New("error: Pack length error")
)

func connectionTest(host string, port uint16) int64 {
	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(int(port)), time.Second*1)
	if err != nil {
		return -1
	}
	conn.Close()
	endTime := time.Now()
	return endTime.UnixMilli() - startTime.UnixMilli()
}

func (qqClient *QQClient) Connect() error {
	var err error
	for i := 0; i < len(qqClient.SsoServerList); i++ {
		qqClient.Conn, err = net.Dial("tcp", qqClient.SsoServerList[i].Host+":"+strconv.Itoa(int(qqClient.SsoServerList[i].Port)))
		if err == nil {
			qqClient.Connected = true
			go qqClient.PackRecvLoop()
			return nil
		}
	}
	return ErrorNoServerIsReachable
}

func (qqClient *QQClient) SendPack(pack []byte, seqence uint16) uint16 {
	qqClient.Conn.Write(pack)
	return seqence
}

func (qqClient *QQClient) PackRecvLoop() {
	lengthBuffer := make([]byte, 4)
	var length int32
	var err error
	var body []byte
	var recvSum int
	var nowRecv int
	var netpackStruct *NetworkPackStruct
	for qqClient.Connected {
		_, err = qqClient.Conn.Read(lengthBuffer)
		if err != nil {
			fmt.Println(err)
			continue
		}
		length = BytesToInt32(lengthBuffer)
		if length < 4 || length > 1024*1024*10 {
			continue
		}
		body = make([]byte, length-4)
		recvSum = 0
		nowRecv = 0
		for {
			nowRecv, err = qqClient.Conn.Read(body[recvSum:])
			if err != nil {
				fmt.Println(err)
				continue
			}
			recvSum += nowRecv
			if recvSum == int(length-4) {
				break
			}
		}
		netpackStruct, err = qqClient.DecodeNetworkPack(body)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if netpackStruct.CommandName == "ConfigPushSvc.PushReq" {
			qqClient.HandleConfigPushRequest(netpackStruct.Body)
		} else if netpackStruct.CommandName == "ConfigPushSvc.PushDomain" {
		} else if netpackStruct.CommandName == "MessageSvc.PushNotify" {
			qqClient.HandlePushNotifyRequest(netpackStruct)
		} else if netpackStruct.CommandName == "OnlinePush.ReqPush" {
			qqClient.HandleOnlinePushRequest(netpackStruct)
		} else {
			qqClient.ResponsePackLock.Lock()
			fmt.Println(netpackStruct.CommandName)
			if channel, ok := qqClient.ResponsePackWaitChannelMap[netpackStruct.Seqence]; ok {
				channel <- netpackStruct
				delete(qqClient.ResponsePackWaitChannelMap, netpackStruct.Seqence)
			} else {
				qqClient.ResponsePackNotHandledMap[netpackStruct.Seqence] = netpackStruct
			}
			qqClient.ResponsePackLock.Unlock()
		}
	}
}

func (qqClient *QQClient) RecvPack(seqence uint16) *NetworkPackStruct {
	qqClient.ResponsePackLock.Lock()
	if netpackStruct, ok := qqClient.ResponsePackNotHandledMap[seqence]; ok {
		delete(qqClient.ResponsePackNotHandledMap, seqence)
		qqClient.ResponsePackLock.Unlock()
		return netpackStruct
	}
	channel := make(chan *NetworkPackStruct)
	qqClient.ResponsePackWaitChannelMap[seqence] = channel
	qqClient.ResponsePackLock.Unlock()
	return <-channel
}
