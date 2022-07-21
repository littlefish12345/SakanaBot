package FishBot

import (
	"bytes"
	"crypto/md5"
	"math/rand"
	"strconv"
	"time"

	"github.com/RomiChan/protobuf/proto"
	goqqprotobuf "github.com/littlefish12345/go-qq-protobuf"
	goqqtea "github.com/littlefish12345/go-qq-tea"
)

func TlvEncode(typeId uint16, data []byte) []byte {
	return append(Int16ToBytes(int16(typeId)), append(Int16ToBytes(int16(uint16(len(data)))), data...)...)
}

func TlvRead(data []byte, tagSizeBitNum int) map[uint16][]byte {
	returnMap := make(map[uint16][]byte)
	var pointer uint32
	var typeId uint16
	var tlvSize uint32
	for {
		if len(data)-int(pointer) < tagSizeBitNum {
			return returnMap
		}
		if tagSizeBitNum == 1 {
			typeId = uint16(data[pointer])
			pointer += 1
		} else if tagSizeBitNum == 2 {
			typeId = uint16(BytesToInt16(data[pointer : pointer+2]))
			pointer += 2
		} else if tagSizeBitNum == 4 {
			typeId = uint16(BytesToInt32(data[pointer : pointer+4]))
			pointer += 4
		}
		if typeId == 255 {
			return returnMap
		}
		tlvSize = uint32(BytesToInt16(data[pointer : pointer+2]))
		pointer += 2
		returnMap[typeId] = data[pointer : pointer+tlvSize]
		pointer += tlvSize
	}
}

func TlvType0x1Encode(uin uint32, ip []byte) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write([]byte{0x00, 0x01}) //1*uint16
	buffer.Write(Int32ToBytes(int32(rand.Uint32())))
	buffer.Write(Int32ToBytes(int32(uin)))
	buffer.Write(Int32ToBytes(int32(uint32(time.Now().Unix()))))
	buffer.Write(ip)
	buffer.Write([]byte{0x00, 0x00}) //1*uint16
	return TlvEncode(0x1, buffer.Bytes())
}

func TlvType0x8Encode(localId uint32) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write([]byte{0x00, 0x00}) //1*uint16
	buffer.Write(Int32ToBytes(int32(localId)))
	buffer.Write([]byte{0x00, 0x00}) //1*uint16
	return TlvEncode(0x8, buffer.Bytes())
}

func TlvType0x18Encode(appId uint32, uin uint32) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write([]byte{0x00, 0x01}) //1*uint16
	buffer.Write(Int32ToBytes(1536))
	buffer.Write(Int32ToBytes(int32(appId)))
	buffer.Write([]byte{0x00, 0x00, 0x00, 0x00}) //1*uint32
	buffer.Write(Int32ToBytes(int32(uint32(uin))))
	buffer.Write([]byte{0x00, 0x00, 0x00, 0x00}) //2*uint16
	return TlvEncode(0x18, buffer.Bytes())
}

func TlvType0x100Encode(ssoVersion uint32, appId uint32, subAppId uint32, appClientVersion uint32, mainSigmap uint32) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write([]byte{0x00, 0x01}) //1*uint16
	buffer.Write(Int32ToBytes(int32(ssoVersion)))
	buffer.Write(Int32ToBytes(int32(appId)))
	buffer.Write(Int32ToBytes(int32(subAppId)))
	buffer.Write(Int32ToBytes(int32(appClientVersion)))
	buffer.Write(Int32ToBytes(int32(mainSigmap)))
	return TlvEncode(0x100, buffer.Bytes())
}

func TlvType0x104Encode(data []byte) []byte {
	return TlvEncode(0x104, data)
}

func TlvType0x107Encode(picType uint16) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(Int16ToBytes(int16(picType)))
	buffer.Write([]byte{0x00, 0x00, 0x00, 0x01}) //1*byte+1*uint16+1*byte
	return TlvEncode(0x107, buffer.Bytes())
}

func TlvType0x106Encode(uin uint32, hashSalt uint32, appId uint32, subAppId uint32, appClientVersion uint32,
	ssoVersion uint32, passwordHash [16]byte, guidAvailable bool, guid, tgtgtKey []byte) []byte {
	keyBody := new(bytes.Buffer)
	keyBody.Write(passwordHash[:])
	keyBody.Write([]byte{0x00, 0x00, 0x00, 0x00})
	if hashSalt != 0 {
		keyBody.Write(Int32ToBytes(int32(hashSalt)))
	} else {
		keyBody.Write(Int32ToBytes(int32(uin)))
	}
	key := md5.Sum(keyBody.Bytes())

	body := new(bytes.Buffer)
	body.Write([]byte{0x00, 0x04})
	body.Write(Int32ToBytes(int32(rand.Uint32())))
	body.Write(Int32ToBytes(int32(ssoVersion)))
	body.Write(Int32ToBytes(int32(appId)))
	body.Write(Int32ToBytes(int32(appClientVersion)))
	if uin == 0 {
		body.Write(Int64ToBytes(int64(hashSalt)))
	} else {
		body.Write(Int64ToBytes(int64(uin)))
	}
	body.Write(Int32ToBytes(int32(uint32(time.Now().Unix()))))
	body.Write([]byte{0x00, 0x00, 0x00, 0x00}) //ip
	body.WriteByte(0x01)                       //save password true
	body.Write(passwordHash[:])
	body.Write(tgtgtKey)
	body.Write([]byte{0x00, 0x00, 0x00, 0x00}) //1*uint32
	if guidAvailable {
		body.WriteByte(0x01)
	} else {
		body.WriteByte(0x00)
	}
	if len(guid) == 0 {
		body.Write(Int32ToBytes(int32(rand.Uint32())))
		body.Write(Int32ToBytes(int32(rand.Uint32())))
		body.Write(Int32ToBytes(int32(rand.Uint32())))
		body.Write(Int32ToBytes(int32(rand.Uint32())))
	} else {
		body.Write(guid)
	}
	body.Write(Int32ToBytes(int32(subAppId)))
	body.Write(Int32ToBytes(1)) //pasword login
	uinString := strconv.FormatInt(int64(uin), 10)
	body.Write(Int16ToBytes(int16(uint16(len(uinString)))))
	body.WriteString(uinString)
	body.Write([]byte{0x00, 0x00}) //?

	return TlvEncode(0x106, goqqtea.NewTeaCipher(key[:]).Encrypt(body.Bytes()))
}

func TlvType0x109Encode(androidId []byte) []byte {
	hash := md5.Sum(androidId)
	return TlvEncode(0x109, hash[:])
}

func TlvType0x116Encode(bitmap uint32, subSigmap uint32) []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(0x00)
	buffer.Write(Int32ToBytes(int32(bitmap)))
	buffer.Write(Int32ToBytes(int32(subSigmap)))
	buffer.WriteByte(0x01)                 //appIdListLength
	buffer.Write(Int32ToBytes(1600000226)) //appIdList
	return TlvEncode(0x116, buffer.Bytes())
}

func TlvType0x128Encode(isGuidFromFileNull bool, isGuidAvailable bool, isGuidChanged bool, model []byte, guid []byte, brand []byte) []byte {
	guidFlag := uint32(0)
	guidSrc := uint32(1)
	guidChange := uint32(0)
	guidFlag |= guidSrc << 24 & 0xFF000000
	guidFlag |= guidChange << 8 & 0xFF00

	buffer := new(bytes.Buffer)
	buffer.Write([]byte{0x00, 0x00}) //1*uint16
	if isGuidFromFileNull {
		buffer.WriteByte(0x01)
	} else {
		buffer.WriteByte(0x00)
	}
	if isGuidAvailable {
		buffer.WriteByte(0x01)
	} else {
		buffer.WriteByte(0x00)
	}
	if isGuidChanged {
		buffer.WriteByte(0x01)
	} else {
		buffer.WriteByte(0x00)
	}
	buffer.Write(Int32ToBytes(int32(guidFlag)))
	if len(model) <= 32 {
		buffer.Write(Int16ToBytes(int16(uint16(len(model)))))
		buffer.Write(model)
	} else {
		buffer.Write(Int16ToBytes(32))
		buffer.Write(model[:32])
	}
	if len(guid) <= 16 {
		buffer.Write(Int16ToBytes(int16(uint16(len(guid)))))
		buffer.Write(guid)
	} else {
		buffer.Write(Int16ToBytes(16))
		buffer.Write(guid[:16])
	}
	if len(brand) <= 16 {
		buffer.Write(Int16ToBytes(int16(uint16(len(brand)))))
		buffer.Write(brand)
	} else {
		buffer.Write(Int16ToBytes(16))
		buffer.Write(brand[:16])
	}
	return TlvEncode(0x128, buffer.Bytes())
}

func TlvType0x124Encode(osType []byte, osVersion []byte, simInfo []byte, address []byte, apn []byte) []byte {
	var networkType uint16 = 1
	if string(apn) == "wifi" {
		networkType++
	}
	buffer := new(bytes.Buffer)
	if len(osType) <= 16 {
		buffer.Write(Int16ToBytes(int16(uint16(len(osType)))))
		buffer.Write(osType)
	} else {
		buffer.Write(Int16ToBytes(16))
		buffer.Write(osType[:16])
	}
	if len(osVersion) <= 16 {
		buffer.Write(Int16ToBytes(int16(uint16(len(osVersion)))))
		buffer.Write(osVersion)
	} else {
		buffer.Write(Int16ToBytes(16))
		buffer.Write(osVersion[:16])
	}
	buffer.Write(Int16ToBytes(int16(networkType)))
	if len(simInfo) <= 16 {
		buffer.Write(Int16ToBytes(int16(uint16(len(simInfo)))))
		buffer.Write(simInfo)
	} else {
		buffer.Write(Int16ToBytes(16))
		buffer.Write(simInfo[:16])
	}
	if len(address) <= 32 {
		buffer.Write(Int16ToBytes(int16(uint16(len(address)))))
		buffer.Write(address)
	} else {
		buffer.Write(Int16ToBytes(32))
		buffer.Write(address[:32])
	}
	if len(apn) <= 16 {
		buffer.Write(Int16ToBytes(int16(uint16(len(apn)))))
		buffer.Write(apn)
	} else {
		buffer.Write(Int16ToBytes(16))
		buffer.Write(apn[:16])
	}
	return TlvEncode(0x124, buffer.Bytes())
}

func TlvType0x141Encode(simInfo []byte, apn []byte) []byte {
	var networkType uint16 = 1
	if string(apn) == "wifi" {
		networkType++
	}
	buffer := new(bytes.Buffer)
	buffer.Write([]byte{0x00, 0x01}) //1*uint16
	buffer.Write(Int16ToBytes(int16(uint16(len(simInfo)))))
	buffer.Write(simInfo)
	buffer.Write(Int16ToBytes(int16(networkType)))
	buffer.Write(Int16ToBytes(int16(uint16(len(apn)))))
	buffer.Write(apn)
	return TlvEncode(0x141, buffer.Bytes())
}

func TlvType0x142Encode(apkId []byte) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write([]byte{0x00, 0x00}) //1*uint16
	if len(apkId) <= 32 {
		buffer.Write(Int16ToBytes(int16(uint16(len(apkId)))))
		buffer.Write(apkId)
	} else {
		buffer.Write(Int16ToBytes(32))
		buffer.Write(apkId[:32])
	}
	return TlvEncode(0x142, buffer.Bytes())
}

func TlvType0x144Encode(deviceInfo *DeviceInfo, isGuidFromFileNull bool, isGuidAvailable bool, isGuidChanged bool) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write([]byte{0x00, 0x05}) //1*uint16
	buffer.Write(TlvType0x109Encode([]byte(deviceInfo.IMEI)))
	buffer.Write(TlvType0x52DEncode(deviceInfo))
	buffer.Write(TlvType0x124Encode([]byte(deviceInfo.OsType), []byte(deviceInfo.Version.Release), []byte(deviceInfo.SimInfo), []byte{}, []byte(deviceInfo.Apn)))
	buffer.Write(TlvType0x128Encode(isGuidFromFileNull, isGuidAvailable, isGuidChanged, []byte(deviceInfo.Model), deviceInfo.Guid, []byte(deviceInfo.Brand)))
	buffer.Write(TlvType0x16EEncode([]byte(deviceInfo.Model)))
	return TlvEncode(0x144, goqqtea.NewTeaCipher(deviceInfo.TgtgtKey).Encrypt(buffer.Bytes()))
}

func TlvType0x145Encode(guid []byte) []byte {
	return TlvEncode(0x145, guid)
}

func TlvType0x147Encode(appId uint32, apkVersion []byte, apkSign []byte) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(Int32ToBytes(int32(appId)))
	if len(apkVersion) <= 32 {
		buffer.Write(Int16ToBytes(int16(uint16(len(apkVersion)))))
		buffer.Write(apkVersion)
	} else {
		buffer.Write(Int16ToBytes(32))
		buffer.Write(apkVersion[:32])
	}
	if len(apkSign) <= 32 {
		buffer.Write(Int16ToBytes(int16(uint16(len(apkSign)))))
		buffer.Write(apkSign)
	} else {
		buffer.Write(Int16ToBytes(32))
		buffer.Write(apkSign[:32])
	}
	return TlvEncode(0x147, buffer.Bytes())
}

func TlvType0x154Encode(seqence uint16) []byte {
	return TlvEncode(0x154, Int32ToBytes(int32(seqence)))
}

func TlvType0x16EEncode(model []byte) []byte {
	return TlvEncode(0x16E, model)
}

func TlvType0x174Encode(data []byte) []byte {
	return TlvEncode(0x174, data)
}

func TlvType0x177Encode(buildTime uint32, sdkVersion string) []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(0x01)
	buffer.Write(Int32ToBytes(int32(buildTime)))
	buffer.Write(Int16ToBytes(int16(uint16(len(sdkVersion)))))
	buffer.WriteString(sdkVersion)
	return TlvEncode(0x177, buffer.Bytes())
}

func TlvType0x17AEncode(SMSAppId uint32) []byte {
	return TlvEncode(0x17A, Int32ToBytes(int32(SMSAppId)))
}

func TlvType0x17CEncode(SMSCode string) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(Int16ToBytes(int16(uint16(len(SMSCode)))))
	buffer.Write([]byte(SMSCode))
	return TlvEncode(0x17C, buffer.Bytes())
}

func TlvType0x187Encode(macAddress []byte) []byte {
	hash := md5.Sum(macAddress)
	return TlvEncode(0x187, hash[:])
}

func TlvType0x188Encode(androidId []byte) []byte {
	hash := md5.Sum(androidId)
	return TlvEncode(0x188, hash[:])
}

func TlvType0x191Encode(canWebVerify byte) []byte {
	return TlvEncode(0x191, []byte{canWebVerify})
}

func TlvType0x193Encode(ticket string) []byte {
	return TlvEncode(0x193, []byte(ticket))
}

func TlvType0x194Encode(imsiHash []byte) []byte {
	return TlvEncode(0x194, imsiHash)
}

func TlvType0x197Encode(data []byte) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(Int16ToBytes(int16(uint16(len(data)))))
	buffer.Write(data)
	return TlvEncode(0x197, buffer.Bytes())
}

func TlvType0x198Encode() []byte {
	return TlvEncode(0x198, []byte{0x00})
}

func TlvType0x202Encode(wifiBSSID []byte, wifiSSID []byte) []byte {
	buffer := new(bytes.Buffer)
	if len(wifiBSSID) <= 16 {
		buffer.Write(Int16ToBytes(int16(uint16(len(wifiBSSID)))))
		buffer.Write(wifiBSSID)
	} else {
		buffer.Write(Int16ToBytes(16))
		buffer.Write(wifiBSSID[:16])
	}
	if len(wifiSSID) <= 32 {
		buffer.Write(Int16ToBytes(int16(uint16(len(wifiSSID)))))
		buffer.Write(wifiSSID)
	} else {
		buffer.Write(Int16ToBytes(32))
		buffer.Write(wifiSSID[:32])
	}
	return TlvEncode(0x202, buffer.Bytes())
}

func TlvType0x401Encode(data []byte) []byte {
	return TlvEncode(0x401, data)
}

func TlvType0x511Encode(domains []string) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(Int16ToBytes(int16(uint16(len(domains)))))
	for _, domain := range domains {
		buffer.WriteByte(0x01)
		buffer.Write(Int16ToBytes(int16(uint16(len(domain)))))
		buffer.WriteString(domain)
	}
	return TlvEncode(0x511, buffer.Bytes())
}

func TlvType0x516Encode(sourceType uint32) []byte {
	return TlvEncode(0x516, Int32ToBytes(int32(sourceType))) //1*uint32
}

func TlvType0x521Encode(productType uint32) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(Int32ToBytes(int32(productType)))
	buffer.Write([]byte{0x00, 0x00}) //1*uint16
	return TlvEncode(0x521, buffer.Bytes())
}

func TlvType0x525Encode(type0x536 []byte) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write([]byte{0x00, 0x01}) //1*uint16
	buffer.Write(type0x536)
	return TlvEncode(0x525, buffer.Bytes())
}

func TlvType0x536Encode(loginExtraData []byte) []byte {
	return TlvEncode(0x536, loginExtraData)
}

func TlvType0x52DEncode(deviceInfo *DeviceInfo) []byte {
	data, _ := proto.Marshal(goqqprotobuf.DeviceInfoBytesStruct{
		Bootloader:   proto.String(deviceInfo.Bootloader),
		ProcVersion:  proto.String(deviceInfo.ProcVersion),
		CodeName:     proto.String(deviceInfo.Version.CodeName),
		Incremental:  proto.String(deviceInfo.Version.Incremental),
		FingerPrint:  proto.String(deviceInfo.FingerPrint),
		BootId:       proto.String(deviceInfo.BootId),
		AndroidId:    proto.String(deviceInfo.AndroidId),
		BaseBand:     proto.String(deviceInfo.BaseBand),
		InnerVersion: proto.String(deviceInfo.Version.Incremental),
	})
	return TlvEncode(0x52D, data)
}
