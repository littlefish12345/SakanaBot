package FishBot

const (
	LoginResponseNeedSlider uint16 = 1
	LoginResponseOtherError uint16 = 2
)

type LoginResponse struct {
	Success         bool
	Error           uint16
	SliderVerifyUrl string
	Message         string
}
