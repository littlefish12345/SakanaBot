package FishBot

import "sync"

type SafeInt32 struct {
	value int32
	lock  sync.Mutex
}

func (safeInt32 *SafeInt32) Get() int32 {
	safeInt32.lock.Lock()
	defer safeInt32.lock.Unlock()
	return safeInt32.value
}

func (safeInt32 *SafeInt32) Set(value int32) {
	safeInt32.lock.Lock()
	defer safeInt32.lock.Unlock()
	safeInt32.value = value
}

func (safeInt32 *SafeInt32) Add(value int32) int32 {
	safeInt32.lock.Lock()
	defer safeInt32.lock.Unlock()
	safeInt32.value += value
	return safeInt32.value
}
