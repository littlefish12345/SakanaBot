package SakanaBot

import (
	"errors"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/littlefish12345/simpwebserv"
)

const (
	sliderVerifyPageHTML = `<!DOCTYPE html>
	<html>
	<head lang="zh-CN">
		<meta charset="UTF-8" />
		<meta name="renderer" content="webkit" />
		<meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no" />
		<title>滑条验证码</title>
	</head>
	<body>
		<div id="cap_iframe" style="width: 230px; height: 220px"></div>
		<script type="text/javascript">
			!(function () {
				var e = document.createElement("script");
				e.type = "text/javascript";
				e.src = "https://captcha.qq.com/template/TCapIframeApi.js" + location.search;
				document.getElementsByTagName("head").item(0).appendChild(e);
				getQueryVariable = function (variable) {
					var query = window.location.search.substring(1);
					var vars = query.split('&');
					for (var i = 0; i < vars.length; i++) {
						var pair = vars[i].split('=');
						if (decodeURIComponent(pair[0]) == variable) {
							return decodeURIComponent(pair[1]);
						}
					}
				}
				e.onload = function () {
					capInit(document.getElementById("cap_iframe"), {
						callback: function (a) {
							var xhr = new XMLHttpRequest();
							xhr.open("GET", "/submitTicket?ticket="+a.ticket, true);
							xhr.onload = function (e) {
								window.close();
							};
							xhr.send();
						},
						showHeader: !1,
					});
				};
			})();
		</script>
	</body>
	</html>`
)

var (
	ErrNoIpAvailable  = errors.New("error: No ip available")
	sliderTicket      chan string
	sliderInternelUrl string
)

func sendSliderVerifyPage(request *simpwebserv.Request) *simpwebserv.Response {
	response := simpwebserv.BuildBasicResponse()
	response.Body.Write([]byte(sliderVerifyPageHTML))
	return response
}

func getSliderResult(request *simpwebserv.Request) *simpwebserv.Response {
	response := simpwebserv.BuildBasicResponse()
	getMap := request.DecodeUrlParameter()
	if sliderTicketString, ok := getMap["ticket"]; ok {
		sliderTicket <- sliderTicketString
	}
	return response
}

func stopSliderServer(request *simpwebserv.Request) *simpwebserv.Response {
	runtime.Goexit()
	return simpwebserv.BuildBasicResponse()
}

func StartSliderCaptchaServer() ([]string, error) { //http url
	var ipList []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			ipList = append(ipList, ip.String())
		}
	}

	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:0")
	if err != nil {
		return []string{}, err
	}
	listener, err := net.ListenTCP("tcp", address)
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	if len(ipList) == 0 {
		return nil, ErrNoIpAvailable
	}

	app := simpwebserv.App()
	app.Register(sendSliderVerifyPage, "/", false)
	app.Register(getSliderResult, "/submitTicket", false)
	app.Register(stopSliderServer, "/stopserver", false)
	go app.Run(simpwebserv.Config{Host: "0.0.0.0", Port: uint16(port), MultiThreadAcceptNum: 1, DisableConsoleLog: true})
	var urlList []string
	for _, ip := range ipList {
		urlList = append(urlList, "http://"+ip+":"+strconv.Itoa(port)+"/")
	}
	sliderInternelUrl = urlList[0]
	sliderTicket = make(chan string)
	return urlList, nil
}

func GetSliderTicket() string {
	sliderTicketString := <-sliderTicket
	cli := http.Client{Timeout: time.Millisecond}
	cli.Get(sliderInternelUrl + "stopserver")
	return sliderTicketString
}

func (qqClient *QQClient) SubmitSliderTicket(ticket string) *LoginResponse {
	if !qqClient.Connected {
		qqClient.Connect()
	}
	netpack := qqClient.RecvPack(qqClient.SendPack(qqClient.BuildLoginSliderSendPack(ticket)))
	return qqClient.DecodeLoginResponseNetworkPack(netpack)
}
