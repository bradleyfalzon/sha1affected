package main

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"
)

func getTLSState(serverName string) (state tls.ConnectionState, err error) {

	if !strings.Contains(serverName, ":") {
		serverName = serverName + ":443"
	}

	conn, err := tls.Dial("tcp", serverName, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.Close()

	state = conn.ConnectionState()

	return
}

func checkRateLimit(serverName string) (exceeded bool, err error) {

	// Currently, this keeps track of each IP address
	// the server has ever connected to. This could
	// require el mucho ram-o. Alternatively, we could
	// have a timer firing every rateLimitSeconds that
	// cleared the global rateLimit map. Then checkRateLimit
	// only needs to check if the entry exists to determine
	// whether a violation has occurred.

	addrs, err := net.LookupIP(serverName)
	if err != nil {
		return
	}

	if len(addrs) == 0 {
		err = errors.New("Could not find IP address for: " + serverName)
		return
	}

	// Set and check rate limits to ensure we're not abusing someone
	rateLimitMux.Lock()
	lastConn, ok := rateLimit[addrs[0].String()]
	rateLimitMux.Unlock()

	if ok {
		// We've previously connected to this IP, check to ensure it was a long time ago
		nextConn := time.Unix(lastConn+int64(rateLimitSeconds), 0)

		if time.Now().Before(nextConn) {
			exceeded = true
			return
		}

	}

	rateLimitMux.Lock()
	rateLimit[addrs[0].String()] = time.Now().Unix()
	rateLimitMux.Unlock()

	return

}
