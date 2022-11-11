package SakanaBot

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
	goqqjce "github.com/littlefish12345/go-qq-jce"
	goqqtea "github.com/littlefish12345/go-qq-tea"
)

func decodeSsoServerInfo(readBuffer *gojce.JceReader) ([]goqqjce.SsoServerInfoStruct, error) {
	readBuffer.SkipHead()
	readBuffer.SkipToId(2)
	readBuffer.SkipHead()
	length := gojce.JceSectionInt32FromBytes(readBuffer)
	var returnList []goqqjce.SsoServerInfoStruct
	var ssoServerInfo goqqjce.SsoServerInfoStruct
	for i := int32(0); i < length; i++ {
		ssoServerInfo = goqqjce.SsoServerInfoStruct{}
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

func ssoServerConnectionTest(waitGroup *sync.WaitGroup, server *goqqjce.SsoServerInfoStruct) int64 { //测试五次tcp连接时间取平均值
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

func sortSsoServerList(serverList *[]goqqjce.SsoServerInfoStruct) {
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

func getSsoServerList(appId uint32, imei string) ([]goqqjce.SsoServerInfoStruct, error) {
	key, _ := hex.DecodeString("F0441F5FF42DA58FDCF7949ABA62D411")
	SsoServerRequest, _ := gojce.Marshal(goqqjce.SsoServerRequestStruct{
		C:      0x01,
		IMSI:   "00000",
		IsWifi: 100,
		AppId:  int32(appId),
		IMEI:   imei,
	})
	payloadData, _ := SsoServerRequest.ToBytes(0)
	requestPack, _ := gojce.Marshal(goqqjce.RequestPacketStruct{
		Version:     3,
		ServantName: "ConfigHttp",
		FuncName:    "HttpServerListReq",
		Buffer:      gojce.JceSectionMapStrBytesToBytes(0, map[string][]byte{"HttpServerListReq": payloadData}),
	})

	finalPack, _ := requestPack.EncodeWithLength()
	teaCipher := goqqtea.NewTeaCipher(key)
	encryptedFinalPack := teaCipher.Encrypt(finalPack)

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

	recvStruct := &goqqjce.RequestPacketStruct{}
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
