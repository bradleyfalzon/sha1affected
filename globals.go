package main

import (
	"regexp"
	"sync"
	"text/template"
)

// Per IP address rate limit in seconds
const rateLimitSeconds = 3

var templates = template.Must(template.ParseFiles("tmpl/header.tmpl", "tmpl/footer.tmpl", "tmpl/homepage.tmpl", "tmpl/results.tmpl", "tmpl/checkForm.tmpl", "tmpl/error.tmpl"))

var URLProtoRE = regexp.MustCompile("^[a-zA-Z0-9]+://")

var rateLimit map[string]int64
var rateLimitMux sync.Mutex

type affectedStages struct {
	Chrome39, Chrome40, Chrome41 chromeWarnings
	Expiry                       bool
	SHA1                         bool
	Certificate                  certificate
	RootCertificate              certificate
	Intermediates                []certificate
}

type certificate struct {
	ExpiryDate string
	ValidFor   string
	SigAlg     string
}

type chromeWarnings struct {
	MinorErrors, NoSecurity, Insecure bool
}

// Pages

type ResultsPage struct {
	PageTitle,
	ServerName string
	Affected affectedStages
}

type ErrorPage struct {
	PageTitle string
	Err       error
}
