package main

type affectedStages struct {
	Chrome39, Chrome40, Chrome41 chromeWarnings
	Expiry                       bool
	SHA1                         bool
	ExpiryDate                   string
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
