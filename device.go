package FishBot

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type OSVersion struct {
	Incremental string
	Release     string
	CodeName    string
	SDK         uint32
}

type DeviceInfo struct {
	Product      string
	Device       string
	Board        string
	Brand        string
	Model        string
	Bootloader   string
	BootId       string
	ProcVersion  string
	BaseBand     string
	VendorName   string
	VendorOSName string
	MacAddress   string
	IpAddress    []byte
	WIFISSID     string
	IMEI         string
	AndroidId    string
	FingerPrint  string
	SimInfo      string
	OsType       string
	Apn          string
	Guid         []byte
	TgtgtKey     []byte
	ImsiHash     []byte
	Version      OSVersion
	Protocol     *Protocol
}

type osVersionJson struct {
	Incremental string `json:"incremental"`
	Release     string `json:"release"`
	CodeName    string `json:"code_name"`
	SDK         uint32 `json:"sdk"`
}

type deviceInfoJson struct {
	Product      string        `json:"product"`
	Device       string        `json:"device"`
	Board        string        `json:"board"`
	Brand        string        `json:"brand"`
	Model        string        `json:"model"`
	Bootloader   string        `json:"boot_loader"`
	BootId       string        `json:"boot_id"`
	ProcVersion  string        `json:"proc_version"`
	BaseBand     string        `json:"base_band"`
	VendorName   string        `json:"vendor_name"`
	VendorOSName string        `json:"vendor_os_name"`
	MacAddress   string        `json:"mac_address"`
	IpAddress    []int         `json:"ip_address"`
	WIFISSID     string        `json:"wifi_ssid"`
	IMEI         string        `json:"imei"`
	AndroidId    string        `json:"android_id"`
	SimInfo      string        `json:"sim_info"`
	OsType       string        `json:"os_type"`
	Apn          string        `json:"apn"`
	ImsiHash     string        `json:"imsi_hash"`
	Version      osVersionJson `json:"version"`
	ProtocolName string        `json:"protocol_name"`
}

func generateUUID(randomData []byte) string {
	return hex.EncodeToString(randomData[0:4]) + "-" + hex.EncodeToString(randomData[4:6]) + "-" +
		hex.EncodeToString(randomData[6:8]) + "-" + hex.EncodeToString(randomData[8:10]) + "-" + hex.EncodeToString(randomData[10:16])
}

func newBootId() string {
	randomData := make([]byte, 16)
	rand.Read(randomData)
	return generateUUID(randomData)
}

func newProcVersion() string {
	rand.Seed(time.Now().Unix())
	return "Linux version 4.19.71-" + strconv.FormatInt(rand.Int63n(0xffffffff-0x10000000)+0x10000000, 16) + " (android-build@github.com)"
}

func newMacAddress() string {
	randomData := make([]byte, 6)
	rand.Read(randomData)
	return strings.ToUpper(hex.EncodeToString(randomData[0:1]) + ":" + hex.EncodeToString(randomData[1:2]) + ":" + hex.EncodeToString(randomData[2:3]) + ":" +
		hex.EncodeToString(randomData[3:4]) + ":" + hex.EncodeToString(randomData[4:5]) + ":" + hex.EncodeToString(randomData[5:6]))
}

func newIpAddress() []byte {
	randomData := make([]byte, 2)
	rand.Read(randomData)
	return []byte{192, 168, randomData[0], randomData[1]}
}

func newIMEI() string {
	return "86" + fmt.Sprintf("%04d", rand.Intn(9999-100)+100) + "0" + fmt.Sprintf("%07d", rand.Intn(9999999-1000000)+1000000)
}

func newAndroidId() string {
	return "BRAND." + fmt.Sprintf("%06d", rand.Intn(999999-1)+1) + "." + fmt.Sprintf("%03d", rand.Intn(999-1)+1)
}

func newOSVersion() OSVersion {
	return OSVersion{
		Incremental: "V13.0.8.0.SKBCNXM",
		Release:     "12",
		CodeName:    "REL",
		SDK:         32,
	}
}

func NewDevice() *DeviceInfo {
	deviceInfo := &DeviceInfo{
		Product:      "missi",
		Device:       "venus",
		Board:        "venus",
		Brand:        "Xiaomi",
		Model:        "MI 11",
		Bootloader:   "unknow",
		BootId:       newBootId(),
		ProcVersion:  newProcVersion(),
		BaseBand:     "",
		VendorName:   "MIUI",
		VendorOSName: "MIUI",
		MacAddress:   newMacAddress(),
		IpAddress:    newIpAddress(),
		WIFISSID:     "<unknown ssid>",
		IMEI:         newIMEI(),
		AndroidId:    newAndroidId(),
		SimInfo:      "T-Mobile",
		OsType:       "android",
		Apn:          "wifi",
		Version:      newOSVersion(),
		Protocol:     getProtocol("AndroidPad"),
	}
	deviceInfo.FingerPrint = deviceInfo.Brand + "/" + deviceInfo.Product + "/" + deviceInfo.Device + ":" +
		deviceInfo.Version.Release + "/" + deviceInfo.AndroidId + "/" + deviceInfo.Version.Incremental + ":user/release-keys"
	hash := md5.Sum(append([]byte(deviceInfo.AndroidId), []byte(deviceInfo.MacAddress)...))
	deviceInfo.Guid = hash[:]
	deviceInfo.TgtgtKey = make([]byte, 16)
	rand.Read(deviceInfo.TgtgtKey)
	deviceInfo.ImsiHash = make([]byte, 16)
	rand.Read(deviceInfo.ImsiHash)
	return deviceInfo
}

func (deviceInfo *DeviceInfo) ToJson() []byte {
	jsonStruct := deviceInfoJson{
		Product:      deviceInfo.Product,
		Device:       deviceInfo.Device,
		Board:        deviceInfo.Board,
		Brand:        deviceInfo.Brand,
		Model:        deviceInfo.Model,
		Bootloader:   deviceInfo.Bootloader,
		BootId:       deviceInfo.BootId,
		ProcVersion:  deviceInfo.ProcVersion,
		BaseBand:     deviceInfo.BaseBand,
		VendorName:   deviceInfo.VendorName,
		VendorOSName: deviceInfo.VendorOSName,
		MacAddress:   deviceInfo.MacAddress,
		IpAddress:    []int{int(deviceInfo.IpAddress[0]), int(deviceInfo.IpAddress[1]), int(deviceInfo.IpAddress[2]), int(deviceInfo.IpAddress[3])},
		WIFISSID:     deviceInfo.WIFISSID,
		IMEI:         deviceInfo.IMEI,
		AndroidId:    deviceInfo.AndroidId,
		SimInfo:      deviceInfo.SimInfo,
		OsType:       deviceInfo.OsType,
		Apn:          deviceInfo.Apn,
		ImsiHash:     hex.EncodeToString(deviceInfo.ImsiHash),
		Version: osVersionJson{
			Incremental: deviceInfo.Version.Incremental,
			Release:     deviceInfo.Version.Release,
			CodeName:    deviceInfo.Version.CodeName,
			SDK:         deviceInfo.Version.SDK,
		},
		ProtocolName: deviceInfo.Protocol.Name,
	}
	data, _ := json.Marshal(jsonStruct)
	return data
}

func (deviceInfo *DeviceInfo) FromJson(data []byte) error {
	var jsonStruct deviceInfoJson
	err := json.Unmarshal(data, &jsonStruct)
	if err != nil {
		return err
	}
	deviceInfo.Product = jsonStruct.Product
	deviceInfo.Device = jsonStruct.Device
	deviceInfo.Board = jsonStruct.Board
	deviceInfo.Brand = jsonStruct.Brand
	deviceInfo.Model = jsonStruct.Model
	deviceInfo.Bootloader = jsonStruct.Bootloader
	deviceInfo.BootId = jsonStruct.BootId
	deviceInfo.ProcVersion = jsonStruct.ProcVersion
	deviceInfo.BaseBand = jsonStruct.BaseBand
	deviceInfo.VendorName = jsonStruct.VendorName
	deviceInfo.VendorOSName = jsonStruct.VendorOSName
	deviceInfo.MacAddress = jsonStruct.MacAddress
	deviceInfo.IpAddress = []byte{byte(jsonStruct.IpAddress[0]), byte(jsonStruct.IpAddress[1]), byte(jsonStruct.IpAddress[2]), byte(jsonStruct.IpAddress[3])}
	deviceInfo.WIFISSID = jsonStruct.WIFISSID
	deviceInfo.IMEI = jsonStruct.IMEI
	deviceInfo.AndroidId = jsonStruct.AndroidId
	deviceInfo.SimInfo = jsonStruct.SimInfo
	deviceInfo.OsType = jsonStruct.OsType
	deviceInfo.Apn = jsonStruct.Apn
	deviceInfo.ImsiHash, _ = hex.DecodeString(jsonStruct.ImsiHash)
	deviceInfo.Version = OSVersion{
		Incremental: jsonStruct.Version.Incremental,
		Release:     jsonStruct.Version.Release,
		CodeName:    jsonStruct.Version.CodeName,
		SDK:         jsonStruct.Version.SDK,
	}
	deviceInfo.Protocol = getProtocol(jsonStruct.ProtocolName)
	deviceInfo.FingerPrint = deviceInfo.Brand + "/" + deviceInfo.Product + "/" + deviceInfo.Device + ":" +
		deviceInfo.Version.Release + "/" + deviceInfo.AndroidId + "/" + deviceInfo.Version.Incremental + ":user/release-keys"
	hash := md5.Sum(append([]byte(deviceInfo.AndroidId), []byte(deviceInfo.MacAddress)...))
	deviceInfo.Guid = hash[:]
	deviceInfo.TgtgtKey = make([]byte, 16)
	rand.Read(deviceInfo.TgtgtKey)
	return nil
}
