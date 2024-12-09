package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	reuse "github.com/libp2p/go-reuseport"
)

const metaServerIP = "xx.xx.xx.xx:9000"

type ServiceType int

const (
	HTTP ServiceType = iota
	HTTPS
	SSH
)

var duration = time.Second * 30

type ReverseProxyInfo struct {
	Type            string
	ReverseAddress  string
	Port            string
	LocalServerType ServiceType
	TlsConfig       struct {
		CertFile string
		KeyFile  string
	}
}

func (r ReverseProxyInfo) LocalAddress() string {
	localAddress := fmt.Sprintf("0.0.0.0:%s", r.Port)

	return localAddress
}

var httpInfoList = []ReverseProxyInfo{
	{
		Type:            "nas",
		ReverseAddress:  "192.168.2.200:8000",
		Port:            "8080",
		LocalServerType: HTTPS,
		TlsConfig: struct {
			CertFile string
			KeyFile  string
		}{
			CertFile: "./cert.pem",
			KeyFile:  "./key.pem",
		},
	},
}

var tcpInfoList = []ReverseProxyInfo{
	{
		Type:            "ssh",
		ReverseAddress:  "192.168.1.68:22",
		Port:            "8082",
		LocalServerType: SSH,
	},
}

func main() {
	var wg sync.WaitGroup

	for idx := range httpInfoList {
		reverseProxyInfo := httpInfoList[idx]
		wg.Add(1)
		safeGo(func() {
			startHttpReverseProxy(reverseProxyInfo)
			wg.Done()
		})
	}

	for idx := range tcpInfoList {
		reverseProxyInfo := tcpInfoList[idx]
		wg.Add(1)
		safeGo(func() {
			startTcpReverseProxy(reverseProxyInfo)
			wg.Done()
		})
	}

	wg.Wait()
	log.Println("================= tcp and http server exit ======================")
}

func generateRandomNumber(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min+1) + min
}

func startHttpReverseProxy(info ReverseProxyInfo) {
	for {
		info.Port = fmt.Sprintf("%d", generateRandomNumber(10000, 60000))
		listenAddress := info.LocalAddress() // 本地监听地址。
		log.Println("start a tcp server.", listenAddress)

		var shutdownHttpServerFunc func() error
		safeGo(func() {
			// 1. 起一个 Http 接受请求，然后转发
			destinationAddress := info.ReverseAddress // 转发地址
			shutdownHttpServerFunc = startHttpProxyServer(listenAddress, destinationAddress, info)
		})

		// 2. tcp 打洞
		diggingATcpHole(listenAddress, metaServerIP, info)

		log.Println("================= socket is disconnect. try to reconnect... ======================")

		// 3. 关闭 Http 服务, 然后重新连接
		if shutdownHttpServerFunc != nil {
			err := shutdownHttpServerFunc()
			if err != nil {
				log.Printf("failed to shutdown https server: %s", err)
			}
		}

		time.Sleep(time.Second * 30)
	}
}

func startHttpProxyServer(listenAddress, destinationAddress string, info ReverseProxyInfo) func() error {
	defer recovery()

	l1, err := reuse.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatalf("reuse.Listen error %v", err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/*allpath", func(c *gin.Context) {
		if c.Request.URL.Path == "/ping" {
			c.JSON(200, "ok")
			return
		}
		reverseProxy(c, destinationAddress)
	})

	r.POST("/*allpath", func(c *gin.Context) {
		reverseProxy(c, destinationAddress)
	})

	r.PUT("/*allpath", func(c *gin.Context) {
		reverseProxy(c, destinationAddress)
	})

	if info.LocalServerType == HTTPS {
		tlsServer := &http.Server{
			Addr:    listenAddress,
			Handler: r,
		}

		if err := tlsServer.ServeTLS(l1, info.TlsConfig.CertFile, info.TlsConfig.KeyFile); err != nil {
			log.Printf("failed to start https server: %s", err)
		}
		return func() error {
			defer recovery()
			if tlsServer != nil {
				return tlsServer.Shutdown(context.Background())
			}
			return nil
		}
	} else {
		if err := r.RunListener(l1); err != nil {
			log.Printf("failed to start https server: %s", err)
		}
	}

	return func() error {
		defer recovery()
		if l1 != nil {
			return l1.Close()
		}

		return nil
	}
}

func diggingATcpHole(localAddress, serverAddress string, info ReverseProxyInfo) {
	defer recovery()
	// 1. 建立到服务器
	c, err := reuse.Dial("tcp", localAddress, serverAddress)
	if err != nil {
		log.Println("failed to connect to server:", err)
		return
	}

	count := 0
	for {
		// 2. 发送数据到服务器
		_, err := c.Write([]byte(info.Type))
		if err != nil {
			log.Println("failed to send to server:", err)
			return
		}

		// 3. 读取服务器返回的数据
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			log.Println("Error reading data:", err)
			return
		}

		// 4. 拿到自己链接服务器的 ip 和 port
		ipPort := string(buf[:n])
		if len(ipPort) > 23 { // 做个简单过滤，防止其他客户端乱发
			log.Println("Error Resp:", ipPort)
			c.Close()
			return
		}

		// 5. 由于是全锥性 NAT，所以可以尝试连接下公网IP和port 看是否连接通。在 Mac os 上这一步很重要，访问以后，防火墙会弹出是否允许外网访问的提示。
		result := testTcpHoleConnection(ipPort, info)
		if !result {
			count++
			if count > 10 {
				return
			}

			time.Sleep(time.Second * 3)
			break
		}

		count = 0
		time.Sleep(duration)
	}
}

func testTcpHoleConnection(ipPort string, info ReverseProxyInfo) bool {
	// 连接自己的
	conn, err := net.DialTimeout("tcp", ipPort, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to server: %v", err)
		return false
	}
	defer func() {
		_ = conn.Close()
	}()

	if info.LocalServerType == HTTPS {
		config := &tls.Config{
			InsecureSkipVerify: true,
		}
		// 为TCP连接添加TLS层
		tlsConn := tls.Client(conn, config)

		// 发起TLS握手
		err = tlsConn.Handshake()
		if err != nil {
			log.Printf("Failed to Handshake: %v", err)
			return false
		}
		defer func() {
			_ = tlsConn.Close()
		}()

		conn = tlsConn
	}

	if info.LocalServerType == HTTPS || info.LocalServerType == HTTP {
		// 构建HTTP GET请求字符串
		request := fmt.Sprintf("GET /ping HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n", ipPort)

		_, err = conn.Write([]byte(request))
		if err != nil {
			log.Printf("Error reading data: %v", err)
			return false
		}
	}

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		log.Printf("Error reading data: %v", err)
		return false
	}

	resp := string(buf)
	if info.LocalServerType == HTTPS || info.LocalServerType == HTTP {
		// 使用 strings.Split 将字符串按换行符分割成多个子字符串
		lines := strings.Split(string(buf), "\n")
		// 获取最后一行数据
		lastLine := lines[len(lines)-1]
		resp = lastLine
	}

	log.Printf("[DigHole][success] tcp = %s resp = %s \n", ipPort, resp)
	return true
}

func reverseProxy(c *gin.Context, proxyURL string) {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = proxyURL
			req.URL.Path = c.Request.URL.Path
			req.URL.RawQuery = c.Request.URL.RawQuery
			req.Header = c.Request.Header
			req.Host = proxyURL
		},
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

func recovery() {
	e := recover()
	if e == nil {
		return
	}

	err := fmt.Errorf("%v", e)
	fmt.Printf("【catch panic】err = %v \n stacktrace:\n%s \n", err, debug.Stack())
}

func safeGo(fn func()) {
	go func() {
		defer recovery()
		fn()
	}()
}

func startTcpReverseProxy(info ReverseProxyInfo) {
	for {
		info.Port = fmt.Sprintf("%d", generateRandomNumber(10000, 60000))

		listenAddress := info.LocalAddress() // 本地监听地址。
		log.Println("start a tcp server.", listenAddress)

		safeGo(func() {
			// 1. 起一个 tcp server 接受请求，然后转发
			destinationAddress := info.ReverseAddress // 转发地址
			startTcpProxyServer(listenAddress, destinationAddress)
		})

		// 2. tcp 打洞
		diggingATcpHole(listenAddress, metaServerIP, info)
		log.Println("================= socket is disconnect. try to reconnect... ======================")
		time.Sleep(time.Second * 30)
	}
}

func startTcpProxyServer(listenAddress, destinationAddress string) {
	// 监听本地的端口

	listener, err := reuse.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddress, err)
	}

	log.Printf("Listening on %s...", listenAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleTcpProxyConnection(conn, destinationAddress)
	}

}

func handleTcpProxyConnection(src net.Conn, destinationAddress string) {
	log.Printf("handleTcpProxyConnection rece tcp client: %v", src.RemoteAddr())

	dest, err := net.Dial("tcp", destinationAddress)
	if err != nil {
		log.Printf("Failed to connect to destination: %v", err)
		src.Close()
		return
	}

	// copy src to dest
	go func() {
		defer src.Close()
		defer dest.Close()
		io.Copy(dest, src)

	}()

	// copy dest to src
	go func() {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)

	}()
}
