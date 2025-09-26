package internal

type Request struct {
	Action         string `json:"action"`
	Service        string `json:"service"`
	Path           string `json:"path"`
	Secret         string `json:"secret"`
	OTP            string `json:"otp"`
	Authentication string `json:"auth"`
}

type Secret struct {
	Value string `json:"value"`
	OTP   string `json:"otp"`
}
