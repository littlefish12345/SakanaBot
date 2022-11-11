package SakanaBot

import (
	"bytes"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
)

type ECDHKey struct {
	ServerPublicKeyVersion uint16
	PublicKey              []byte
	ShareKey               []byte
}

const serverPublicKey = "04EBCA94D733E399B2DB96EACDD3F69A8BB0F74224E2B44E3357812211D2E62EFBC91BB553098E25E33A799ADC7F76FEB208DA7C6522CDB0719A305180CC54A82E"

func NewECDHKey() *ECDHKey {
	ECDH := &ECDHKey{
		ServerPublicKeyVersion: 1,
	}
	ECDH.LoadKey(serverPublicKey)
	return ECDH
}

func (key *ECDHKey) LoadKey(publicKeyString string) {
	curve := elliptic.P256()
	publicKey, _ := hex.DecodeString(publicKeyString)
	privateKey, privateX, privateY, _ := elliptic.GenerateKey(curve, rand.Reader)
	publicX, publicY := elliptic.Unmarshal(curve, publicKey)
	x, _ := curve.ScalarMult(publicX, publicY, privateKey)
	xHash := md5.Sum(x.Bytes()[:16])
	key.ShareKey = xHash[:]
	key.PublicKey = elliptic.Marshal(curve, privateX, privateY)
}

func (key *ECDHKey) GetPublicKey(uin int64) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", "https://keyrotate.qq.com/rotate_key?cipher_suite_ver=305&uin="+strconv.FormatInt(uin, 10), bytes.NewReader(nil))
	if err != nil {
		return
	}

	req.Header.Set("Host", "keyrotate.qq.com")
	req.Header.Set("User-Agent", "QQ/8.4.1.2703 CFNetwork/1126")
	req.Header.Set("Net-Type", "Wifi")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	recvData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var dataMap interface{}
	json.Unmarshal(recvData, &dataMap)
	key.ServerPublicKeyVersion = uint16(dataMap.(map[string]interface{})["PubKeyMeta"].(map[string]interface{})["KeyVer"].(float64))
	key.LoadKey(dataMap.(map[string]interface{})["PubKeyMeta"].(map[string]interface{})["PubKey"].(string))
}
