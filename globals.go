package main

import (
	"sync"
	"text/template"
)

// Per IP address rate limit in seconds
const rateLimitSeconds = 3

var templates = template.Must(template.ParseFiles("tmpl/header.tmpl", "tmpl/footer.tmpl", "tmpl/homepage.tmpl", "tmpl/results.tmpl", "tmpl/checkForm.tmpl"))

var rateLimit map[string]int64
var rateLimitMux sync.Mutex

type affectedStages struct {
	Chrome39, Chrome40, Chrome41 chromeWarnings
	Expiry                       bool
	SHA1                         bool
	ExpiryDate                   string
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
