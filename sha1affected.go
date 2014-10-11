package main

import (
	"fmt"
	"log"
	"net/http"
	"text/template"
)

var templates = template.Must(template.ParseFiles("tmpl/header.tmpl", "tmpl/footer.tmpl", "tmpl/homepage.tmpl", "tmpl/results.tmpl", "tmpl/checkForm.tmpl"))

func main() {

	startWebServer()

	serverName := "yahoo.com"

	affected, err := checkServer(serverName)
	if err != nil {
		log.Fatalln(err)
	}

	if affected.SHA1 && affected.Expiry {
		fmt.Println("You have a SHA1 certificate and an expiry date that will be affected.")
		fmt.Printf("%#v\n", affected)
		fmt.Printf("Chrome 39: Minor Errors %v, No Security %v, Insecure %v\n", affected.Chrome39.MinorErrors, affected.Chrome39.NoSecurity, affected.Chrome39.Insecure)
		fmt.Printf("Chrome 40: Minor Errors %v, No Security %v, Insecure %v\n", affected.Chrome40.MinorErrors, affected.Chrome40.NoSecurity, affected.Chrome40.Insecure)
		fmt.Printf("Chrome 41: Minor Errors %v, No Security %v, Insecure %v\n", affected.Chrome41.MinorErrors, affected.Chrome41.NoSecurity, affected.Chrome41.Insecure)
	} else if affected.SHA1 {
		fmt.Println("You have a SHA1 certificate, but are not affected because of your end-identity expiry date:", affected.ExpiryDate)
	} else {
		fmt.Println("You don't have any SHA1 certificates in your chain. Good for you.")
	}

}

func startWebServer() {

	http.HandleFunc("/", homepageHandler)
	http.HandleFunc("/results", resultsHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Listening....")
	http.ListenAndServe(":3000", nil)

}

func checkServer(serverName string) (affected affectedStages, err error) {

	state, err := getTLSState(serverName)
	if err != nil {
		return
	}

	affected, err = datesAffected(state.PeerCertificates[0].NotAfter)
	if err != nil {
		log.Fatal(err)
	}

	containsSHA1(state.PeerCertificates, &affected)

	return

}
