package FishBot

import "fmt"

const (
	LoginMethodPassword uint16 = 0
)

func (qqClient *QQClient) Login(method uint16) *LoginResponse {
	if !qqClient.Connected {
		qqClient.connect()
	}
	if method == LoginMethodPassword {
		qqClient.SendPack(qqClient.BuildLoginPack())
		netpack, _ := qqClient.RecvPack()
		responseType, encryptType, uin, seqence, returnCode, message, commandName, body, _ := qqClient.DecodeNetworkPack(netpack)
		fmt.Println(responseType, encryptType, uin, seqence, returnCode, message, commandName, body)
		command, uin, responsePackBody := qqClient.DecodeResponsePack(body)
		fmt.Println(command, uin)
		fmt.Println(responsePackBody)
		return qqClient.DecodeLoginResponse(responsePackBody)
	}
	return nil
}

func (qqClient *QQClient) RequestSMSCode() bool {
	if !qqClient.Connected {
		qqClient.connect()
	}
	qqClient.SendPack(qqClient.BuildLoginSMSRequestPack())
	netpack, _ := qqClient.RecvPack()
	responseType, encryptType, uin, seqence, returnCode, message, commandName, body, _ := qqClient.DecodeNetworkPack(netpack)
	fmt.Println(responseType, encryptType, uin, seqence, returnCode, message, commandName, body)
	command, uin, responsePackBody := qqClient.DecodeResponsePack(body)
	fmt.Println(command, uin)
	fmt.Println(responsePackBody)
	return qqClient.DecodeLoginResponse(responsePackBody).Error == LoginResponseNeedSMS
}

func (qqClient *QQClient) SubmitSMSCode(SMSCode string) *LoginResponse {
	if !qqClient.Connected {
		qqClient.connect()
	}
	qqClient.SendPack(qqClient.BuildLoginSMSSubmitPack(SMSCode))
	netpack, _ := qqClient.RecvPack()
	responseType, encryptType, uin, seqence, returnCode, message, commandName, body, _ := qqClient.DecodeNetworkPack(netpack)
	fmt.Println(responseType, encryptType, uin, seqence, returnCode, message, commandName, body)
	command, uin, responsePackBody := qqClient.DecodeResponsePack(body)
	fmt.Println(command, uin)
	fmt.Println(responsePackBody)
	return qqClient.DecodeLoginResponse(responsePackBody)
}
