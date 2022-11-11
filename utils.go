package SakanaBot

import (
	"encoding/binary"
	"math"
)

func Int16ToBytes(i int16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(i))
	return buf
}

func BytesToInt16(bytes []byte) int16 {
	return int16(binary.BigEndian.Uint16(bytes))
}

func Int32ToBytes(i int32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return buf
}

func BytesToInt32(bytes []byte) int32 {
	return int32(binary.BigEndian.Uint32(bytes))
}

func Int64ToBytes(i int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

func BytesToInt64(bytes []byte) int64 {
	return int64(binary.BigEndian.Uint64(bytes))
}

func Float32ToByte(float float32) []byte {
	bits := math.Float32bits(float)
	return Int32ToBytes(int32(bits))
}

func BytesToFloat32(bytes []byte) float32 {
	return math.Float32frombits(uint32(BytesToInt32(bytes)))
}

func Float64ToByte(float float64) []byte {
	bits := math.Float64bits(float)
	return Int64ToBytes(int64(bits))
}

func BytesToFloat64(bytes []byte) float64 {
	return math.Float64frombits(uint64(BytesToInt64(bytes)))
}
