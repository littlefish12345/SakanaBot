package FishBot

const (
	LoginResponseNeedSlider    uint16 = 1
	LoginResponseNeedSMS       uint16 = 2
	LoginResponseNeedWebVerify uint16 = 3
	LoginResponseOtherError    uint16 = 4
)

type LoginResponse struct {
	Success         bool
	Error           uint16
	SliderVerifyUrl string
	SMSPhoneNum     string
	Message         string
}
