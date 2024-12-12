const localListenTcpIPPort = "0.0.0.0:9000"
const localListenHttpIPPort = "0.0.0.0:9001"

func main() {
	go startTcpServer()
	startListenHttpSever()
}

func startTcpServer() {
	listener, err := net.Listen("tcp", localListenTcpIPPort)
	if err != nil {
		fmt.Println("Error starting TCP server:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Server is listening on ", localListenTcpIPPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		SafeGo(func() {
			handleConnection(conn)
		})
	}
}

type clientInfo struct {
	UpdateTime time.Time
	Port       string
	Type       string
}

var look = sync.RWMutex{}
var clients = map[string]clientInfo{}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Error reading data:", err)
			return
		}

		const layout = "2006-01-02 15:04:05"
		receivedMsg := string(buf[:n])
		now := time.Now().Format(layout)
		fmt.Printf("[%s Received %s]: %s\n", now, conn.RemoteAddr(), receivedMsg)
		if len(receivedMsg) > 4 {
			fmt.Println("receive long message ", receivedMsg)
			return
		}

		_, prot, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			fmt.Println("Error net.SplitHostPort:", err)

			continue
		}

		info := clientInfo{
			UpdateTime: time.Now(),
			Port:       prot,
			Type:       receivedMsg,
		}

		look.Lock()
		clients[info.Type] = info
		look.Unlock()

		message := []byte(conn.RemoteAddr().String())
		_, err = conn.Write(message)
		if err != nil {
			fmt.Println("Error sending response:", err)
			continue
		}
	}
}

func startListenHttpSever() {
	http.HandleFunc("/", handlerGetClientInfo)
	fmt.Printf("Starting http server at port %s...\n", localListenHttpIPPort)
	if err := http.ListenAndServe(localListenHttpIPPort, nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}

func handlerGetClientInfo(w http.ResponseWriter, r *http.Request) {
	look.RLock()
	defer look.RUnlock()
	data, err := json.Marshal(clients)

	_, err = w.Write(data)
	if err != nil {
		fmt.Println("Error sending response:", err)
		return
	}

	return
}

func Recovery() {
	e := recover()
	if e == nil {
		return
	}

	err := fmt.Errorf("%v", e)
	fmt.Printf("【catch panic】err = %v \n stacktrace:\n%s \n", err, debug.Stack())
}

func SafeGo(fn func()) {
	go func() {
		defer Recovery()
		fn()
	}()
}
