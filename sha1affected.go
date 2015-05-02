package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

var caPool *x509.CertPool
var debug *bool

func main() {

	port := flag.Int("port", 3000, "Port number for web server to listen on.")
	serverName := flag.String("connect", "", "Check a single server and exit.")
	rootCAFile := flag.String("cafile", "", "Load root certificates from this file.")
	debug = flag.Bool("v", false, "Run in debug mode")

	flag.Parse()

	if *rootCAFile != "" {
		parseCAFile(*rootCAFile)
	}

	if *serverName == "" {
		startWebServer(*port)
	} else {
		cliCheck(*serverName)
	}

}

// Parse a file for root CA certificates instead of using system cas
func parseCAFile(rootCAFile string) (err error) {
	log.Println("Loading root certificates from:", rootCAFile)

	caPool = x509.NewCertPool()

	fileBytes, err := ioutil.ReadFile(rootCAFile)

	if err != nil {
		return
	}

	if ok := caPool.AppendCertsFromPEM(fileBytes); !ok {
		return errors.New("Could not read certs from rootCAFile: " + rootCAFile)
	}

	return
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
		fmt.Printf("You have a SHA1 certificate and an expiry date (%s) that will be affected.\n", affected.Certificate.ExpiryDate)
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

	if *debug {
		log.Printf("PeerCertificates: %#v\n", state.PeerCertificates)
		log.Printf("VerifiedChains (count: %d): %#v\n", len(state.VerifiedChains), state.VerifiedChains)

		for _, chain := range state.VerifiedChains {
			log.Printf("Chain: %#v\n", chain)
			for _, cert := range chain {
				log.Printf("\tSubject: %#v\n", cert.Subject.CommonName)
				log.Printf("\tIssuer: %#v\n", cert.Issuer.CommonName)
				log.Printf("\tSignatureAlg: %#v\n", cert.SignatureAlgorithm)
			}
		}
	}

	affected, err = datesAffected(state.PeerCertificates[0].NotAfter)
	if err != nil {
		log.Fatal(err)
	}

	if len(state.VerifiedChains) == 0 {
		log.Printf("Error, found %d PeerCertificates and %d verified chains\n", len(state.PeerCertificates), len(state.VerifiedChains))
		err = errors.New("Could not verify certificate chain, are you missing an intermediate certificate?")
		return
	}

	// Choose the first verified chain
	checkChain := state.VerifiedChains[0]

	// Check if there's another chain that doesn't have sha1, chances are Google won't have an issue with this one
CheckAltChains:
	for _, chain := range state.VerifiedChains {
		for _, cert := range chain {
			if containsSHA1, _ := certSigAlg(cert); !containsSHA1 && !isRootCA(cert) {
				checkChain = chain
				break CheckAltChains
			}
		}
	}

	if *debug {
		log.Println("Chosen chain:")
		for _, cert := range checkChain {
			log.Printf("\tSubject: %#v\n", cert.Subject.CommonName)
			log.Printf("\tIssuer: %#v\n", cert.Issuer.CommonName)
			log.Printf("\tSignatureAlg: %#v\n", cert.SignatureAlgorithm)
		}
	}

	analyseCerts(checkChain, &affected)

	log.Println("Finished request")

	return

}
