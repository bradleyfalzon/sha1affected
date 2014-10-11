package main

import (
	"crypto/tls"
	"strings"
)

func getTLSState(serverName string) (state tls.ConnectionState, err error) {

	if !strings.Contains(serverName, ":") {
		serverName = serverName + ":443"
	}

	conn, err := tls.Dial("tcp", serverName, &tls.Config{})
	if err != nil {
		return
	}
	defer conn.Close()

	state = conn.ConnectionState()

	return
}
