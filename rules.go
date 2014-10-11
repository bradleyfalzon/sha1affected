package main

import (
	"crypto/x509"
	"time"
)

func datesAffected(expiry time.Time) (affected affectedStages, err error) {

	dateJan2016, dateJun2016, dateJan2017, err := getDates()
	if err != nil {
		return
	}

	affected.ExpiryDate = expiry.Format("2006-01-02")

	// Do stage 1 checks (Chrome 39)
	//	if certificate expires on or after 2017-01-01
	//		- secure but with minor errors
	if equalOrAfter(expiry, dateJan2017) {
		affected.Expiry = true
		affected.Chrome39.MinorErrors = true
	}

	// Do stage 2 checks (Chrome 40)
	//	if certificate expires between 2016-06-01 to 2016-12-31
	//		- secure but with minor errors
	//	if certificate expires after 2017-01-01
	//		- neutral, lacking security
	if equalOrAfter(expiry, dateJan2017) {
		affected.Expiry = true
		affected.Chrome40.NoSecurity = true
	} else if equalOrAfter(expiry, dateJun2016) {
		affected.Expiry = true
		affected.Chrome40.MinorErrors = true
	}

	// Do stage 3 checks (Chrome 41)
	//	if certificate expires between 2016-01-01 to 2016-12-31
	//		- secure but with minor errors
	//	if certificate expires after 2017-01-01
	//		- insecure error
	if equalOrAfter(expiry, dateJan2017) {
		affected.Expiry = true
		affected.Chrome41.Insecure = true
	} else if equalOrAfter(expiry, dateJan2016) {
		affected.Expiry = true
		affected.Chrome41.MinorErrors = true
	}

	return

}

func containsSHA1(certs []*x509.Certificate, affected *affectedStages) {

	for k, cert := range certs {
		if k == len(certs)-1 {
			// Ignore root certificate, this simply assumes that the certificates are returned
			// in a gurantee order, which may only be conincidental and not guranteed.
			// TODO check if crypto/tls is even returning this if the server didn't send it.
			return
		}

		switch cert.SignatureAlgorithm {
		case x509.SHA1WithRSA:
			affected.SHA1 = true
		case x509.DSAWithSHA1:
			affected.SHA1 = true
		case x509.ECDSAWithSHA1:
			affected.SHA1 = true
		}

	}

}
