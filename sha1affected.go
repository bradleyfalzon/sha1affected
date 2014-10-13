package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {

	port := flag.Int("port", 3000, "Port number for web server to listen on.")
	serverName := flag.String("connect", "", "Check a single server and exit.")

	flag.Parse()

	if *serverName == "" {
		startWebServer(*port)
	} else {
		cliCheck(*serverName)
	}

}

func cliCheck(serverName string) {

	log.Println("Checking server:", serverName)

	host, err := parseServerName(serverName)
	if err != nil {
		return
	}

	affected, err := checkServer(host)
	if err != nil {
		log.Fatalln(err)
	}

	if affected.SHA1 && affected.Expiry {
		fmt.Printf("You have a SHA1 certificate and an expiry date (%s) that will be affected.", affected.Certificate.ExpiryDate)
		fmt.Printf("Chrome 39: Minor Errors %v, No Security %v, Insecure %v\n", affected.Chrome39.MinorErrors, affected.Chrome39.NoSecurity, affected.Chrome39.Insecure)
		fmt.Printf("Chrome 40: Minor Errors %v, No Security %v, Insecure %v\n", affected.Chrome40.MinorErrors, affected.Chrome40.NoSecurity, affected.Chrome40.Insecure)
		fmt.Printf("Chrome 41: Minor Errors %v, No Security %v, Insecure %v\n", affected.Chrome41.MinorErrors, affected.Chrome41.NoSecurity, affected.Chrome41.Insecure)
	} else if affected.SHA1 {
		fmt.Println("You have a SHA1 certificate, but are not affected because of your end-identity expiry date:", affected.Certificate.ExpiryDate)
	} else {
		fmt.Println("You don't have any SHA1 certificates in your chain. Good for you.")
	}

}

func startWebServer(port int) {

	rateLimit = make(map[string]int64)

	http.HandleFunc("/", homepageHandler)
	http.HandleFunc("/results", resultsHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Starting web server on port:", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	log.Println("Finished listening....")

}

func checkServer(host string) (affected affectedStages, err error) {

	state, err := getTLSState(host)
	if err != nil {
		return
	}

	affected, err = datesAffected(state.PeerCertificates[0].NotAfter)
	if err != nil {
		log.Fatal(err)
	}

	analyseCerts(state.PeerCertificates, &affected)

	log.Println("Finished request")

	return

}
