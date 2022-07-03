package FishBot

import (
	"bytes"
	"compress/zlib"
	"io/ioutil"
	"strconv"

	goqqtea "github.com/littlefish12345/go-qq-tea"
)

func (qqClient *QQClient) DecodeNetworkPack(data []byte) (uint32, byte, int64, uint16, int32, string, string, []byte, error) { //responseType encryptType uin seqence returnCode message commandName body
	responseType := BytesToInt32(data[0:4])
	encryptType := data[4]
	uinLenght := BytesToInt32(data[6:10]) - 4
	uin, _ := strconv.ParseInt(string(data[10:10+uinLenght]), 10, 64)
	ssoPackData := data[10+uinLenght:]
	if encryptType == NetpackEncryptD2Key {

	} else if encryptType == NetpackEncryptEmptyKey {
		ssoPackData = goqqtea.NewTeaCipher(make([]byte, 16)).Decrypt(ssoPackData)
	}

	headLength := BytesToInt32(ssoPackData[0:4]) - 4
	if headLength < 4 || headLength > int32(len(ssoPackData)+4) {
		return 0, 0, 0, 0, 0, "", "", nil, ErrorPackLengthError
	}
	head := ssoPackData[4 : 4+headLength]
	seqence := BytesToInt32(head[0:4])
	returnCode := BytesToInt32(head[4:8])
	messageLength := BytesToInt32(head[8:12]) - 4
	message := string(head[12 : 12+messageLength])
	commandNameLength := BytesToInt32(head[12+messageLength:16+messageLength]) - 4
	commandName := string(head[16+messageLength : 16+messageLength+commandNameLength])
	compressedFlag := BytesToInt32(head[16+messageLength+commandNameLength : 20+messageLength+commandNameLength])

	bodyLenght := BytesToInt32(ssoPackData[4+headLength : 8+headLength])
	body := ssoPackData[8+headLength:]
	if bodyLenght > 0 && bodyLenght < int32(len(body)) {
		body = body[:bodyLenght]
	}
	if compressedFlag == 1 {
		bodyCompressReader, _ := zlib.NewReader(bytes.NewReader(body))
		body, _ = ioutil.ReadAll(bodyCompressReader)
		bodyCompressReader.Close()
	}
	return uint32(responseType), encryptType, uin, uint16(seqence), returnCode, message, commandName, body, nil
}

func (qqClient *QQClient) DecodeResponsePack(data []byte) (uint16, int64, []byte) { //command uin body
	flag := data[0]
	if flag != 2 {
		return 0, 0, nil
	}
	command := BytesToInt16(data[5:7])
	uin := int64(BytesToInt32(data[9:13]))
	encryptType := data[14]
	body := data[16 : len(data)-1]
	if encryptType == 0 {
		body = goqqtea.NewTeaCipher(qqClient.ECDHKey.ShareKey).Decrypt(body)
	}
	return uint16(command), uin, body
}

func (qqClient *QQClient) DecodeLoginResponse(data []byte) {

}
