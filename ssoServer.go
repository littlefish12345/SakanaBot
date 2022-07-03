package FishBot

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	gojce "github.com/littlefish12345/go-jce"
	goqqtea "github.com/littlefish12345/go-qq-tea"
)

type SsoServerRequestStruct struct {
	Uin     int64  `jceId:"1"`
	Timeout int64  `jceId:"2"`
	C       byte   `jceId:"3"` //一直为0x01
	IMSI    string `jceId:"4"`
	IsWifi  int32  `jceId:"5"` //true=100, false=1
	AppId   int32  `jceId:"6"`
	IMEI    string `jceId:"7"`
	CellId  int64  `jceId:"8"`
	I       int64  `jceId:"9"`
	J       int64  `jceId:"10"`
	K       int64  `jceId:"11"`
	L       bool   `jceId:"12"`
	M       int64  `jceId:"13"`
}

type SsoServerInfoStruct struct {
	Host     string `jceId:"1"`
	Port     int32  `jceId:"2"`
	Location string `jceId:"8"`
}

type RequestPacketStruct struct {
	Version     int16             `jceId:"1"`
	PkgType     byte              `jceId:"2"`
	MsgType     int32             `jceId:"3"`
	ReqId       int32             `jceId:"4"`
	ServantName string            `jceId:"5"`
	FuncName    string            `jceId:"6"`
	Buffer      []byte            `jceId:"7"`
	Timeout     int32             `jceId:"8"`
	Context     map[string]string `jceId:"9"`
	Status      map[string]string `jceId:"10"`
}

func decodeSsoServerInfo(readBuffer *gojce.JceReader) ([]SsoServerInfoStruct, error) {
	readBuffer.SkipHead()
	readBuffer.SkipToId(2)
	readBuffer.SkipHead()
	length := gojce.JceSectionInt32FromBytes(readBuffer)
	var returnList []SsoServerInfoStruct
	var ssoServerInfo SsoServerInfoStruct
	for i := int32(0); i < length; i++ {
		ssoServerInfo = SsoServerInfoStruct{}
		readBuffer.SkipHead()
		ssoServerInfo.Host = gojce.JceSectionStringFromBytes(readBuffer)
		ssoServerInfo.Port = gojce.JceSectionInt32FromBytes(readBuffer)
		readBuffer.SkipToId(8)
		ssoServerInfo.Location = gojce.JceSectionStringFromBytes(readBuffer)
		readBuffer.SkipToStructEnd()
		if strings.Contains(ssoServerInfo.Host, "com") {
			continue
		}
		returnList = append(returnList, ssoServerInfo)
	}
	return returnList, nil
}

func ssoServerConnectionTest(waitGroup *sync.WaitGroup, server *SsoServerInfoStruct) int64 { //测试五次tcp连接时间取平均值
	var successTimes int64
	var sumTime int64
	var nowTime int64
	for i := 0; i < 5; i++ {
		nowTime = connectionTest(server.Host, uint16(server.Port))
		if nowTime != -1 {
			successTimes++
			sumTime += nowTime
		}
	}
	waitGroup.Done()
	if successTimes != 0 {
		return sumTime / successTimes
	}
	return -1
}

func sortSsoServerList(serverList *[]SsoServerInfoStruct) {
	connectionTimeList := make([]int64, len(*serverList))
	waitGroup := sync.WaitGroup{}
	for i := 0; i < len(*serverList); i++ {
		waitGroup.Add(1)
		go func(i int, waitGroup *sync.WaitGroup) {
			connectionTimeList[i] = ssoServerConnectionTest(waitGroup, &(*serverList)[i])
		}(i, &waitGroup)
	}
	waitGroup.Wait()
	sort.Slice(*serverList, func(i int, j int) bool {
		return (connectionTimeList[i] < connectionTimeList[j]) && (connectionTimeList[i] != -1)
	})
}

func getSsoServerList(appId uint32, imei string) ([]SsoServerInfoStruct, error) {
	key, _ := hex.DecodeString("F0441F5FF42DA58FDCF7949ABA62D411")
	SsoServerRequest, err := gojce.Marshal(SsoServerRequestStruct{C: 0x01, IMSI: "00000", IsWifi: 100, AppId: int32(appId), IMEI: imei})
	if err != nil {
		return nil, err
	}
	payloadData, err := SsoServerRequest.ToBytes(0)
	if err != nil {
		return nil, err
	}

	bufferMap := make(map[string][]byte)
	bufferMap["HttpServerListReq"] = payloadData
	bufferMapData := gojce.JceSectionMapStrBytesToBytes(0, bufferMap)
	if err != nil {
		return nil, err
	}
	requestPack, err := gojce.Marshal(RequestPacketStruct{Version: 3, ServantName: "ConfigHttp", FuncName: "HttpServerListReq", Buffer: bufferMapData})
	if err != nil {
		return nil, err
	}
	finalPack, err := requestPack.EncodeWithLength()
	teaCipher := goqqtea.NewTeaCipher(key)
	encryptedFinalPack := teaCipher.Encrypt(finalPack)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}

	req, err := http.NewRequest("POST", "https://configsvr.msf.3g.qq.com/configsvr/serverlist.jsp", bytes.NewReader(encryptedFinalPack))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Host", "configsvr.msf.3g.qq.com")
	req.Header.Set("User-Agent", "QQ/8.4.1.2703 CFNetwork/1126")
	req.Header.Set("Net-Type", "Wifi")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(finalPack)))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	recvData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	decryptedRecvData := teaCipher.Decrypt(recvData)

	recvStruct := &RequestPacketStruct{}
	err = gojce.Unmarshal(decryptedRecvData[4:], recvStruct)
	if err != nil {
		return nil, err
	}
	recvPayloadDecode := gojce.JceSectionMapStrBytesFromBytes(gojce.NewJceReader(recvStruct.Buffer))
	ssoServerInfoListBytes := recvPayloadDecode["HttpServerListRes"]
	ssoServerInfoList, err := decodeSsoServerInfo(gojce.NewJceReader(ssoServerInfoListBytes))
	if err != nil {
		return nil, err
	}
	sortSsoServerList(&ssoServerInfoList)
	return ssoServerInfoList, nil
}
