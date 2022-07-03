package FishBot

import (
	"errors"
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

func (qqClient *QQClient) connect() error {
	var err error
	for i := 0; i < len(qqClient.SsoServerList); i++ {
		qqClient.Conn, err = net.Dial("tcp", qqClient.SsoServerList[i].Host+":"+strconv.Itoa(int(qqClient.SsoServerList[i].Port)))
		if err == nil {
			qqClient.Connected = true
			return nil
		}
	}
	return ErrorNoServerIsReachable
}

func (qqClient *QQClient) SendPack(pack []byte) {
	qqClient.Conn.Write(pack)
}

func (qqClient *QQClient) RecvPack() ([]byte, error) {
	lengthBuffer := make([]byte, 4)
	_, err := qqClient.Conn.Read(lengthBuffer)
	if err != nil {
		return nil, err
	}
	length := BytesToInt32(lengthBuffer)
	if length < 4 || length > 1024*1024*10 {
		return nil, ErrorPackLengthError
	}
	body := make([]byte, length-4)
	var recvSum int = 0
	var nowRecv int = 0
	for {
		nowRecv, err = qqClient.Conn.Read(body[recvSum:])
		if err != nil {
			return nil, err
		}
		recvSum += nowRecv
		if recvSum == int(length-4) {
			break
		}
	}
	return body, nil
}
