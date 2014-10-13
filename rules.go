package main

import (
	"crypto/x509"
	"strings"
	"time"
)

func datesAffected(expiry time.Time) (affected affectedStages, err error) {

	dateJan2016, dateJun2016, dateJan2017, err := getDates()
	if err != nil {
		return
	}

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

func analyseCerts(certs []*x509.Certificate, affected *affectedStages) {

	for _, cert := range certs {
		summary := certificate{}

		if !isRootCA(cert) {
			// Ignore root certificate as no-one trusts the signature itself

			switch cert.SignatureAlgorithm {
			case x509.SHA1WithRSA:
				summary.SigAlg = "SHA1"
				affected.SHA1 = true
			case x509.DSAWithSHA1:
				summary.SigAlg = "SHA1"
				affected.SHA1 = true
			case x509.ECDSAWithSHA1:
				summary.SigAlg = "SHA1"
				affected.SHA1 = true
			case x509.MD5WithRSA:
				summary.SigAlg = "MD5"
			case x509.SHA256WithRSA:
				summary.SigAlg = "SHA256"
			case x509.SHA384WithRSA:
				summary.SigAlg = "SHA384"
			case x509.SHA512WithRSA:
				summary.SigAlg = "SHA512"
			case x509.DSAWithSHA256:
				summary.SigAlg = "SHA256"
			case x509.ECDSAWithSHA256:
				summary.SigAlg = "SHA256"
			case x509.ECDSAWithSHA384:
				summary.SigAlg = "SHA384"
			case x509.ECDSAWithSHA512:
				summary.SigAlg = "SHA512"
			default:
				summary.SigAlg = "Unknown"
			}

		}

		summary.ExpiryDate = cert.NotAfter.Format("2006-01-02")
		if len(cert.DNSNames) == 0 {
			summary.ValidFor = cert.Subject.CommonName
		} else {
			summary.ValidFor = strings.Join(cert.DNSNames, ", ")
		}

		if !cert.IsCA {
			affected.Certificate = summary
		} else if isRootCA(cert) {
			affected.RootCertificate = summary
		} else {
			affected.Intermediates = append(affected.Intermediates, summary)
		}

	}

}

func isRootCA(cert *x509.Certificate) bool {
	if !cert.IsCA {
		// Ignore self signed certificates
		return false
	}

	if cert.Issuer.CommonName == cert.Subject.CommonName {
		// One day, actually check if the cert is actually signing itself
		return true
	}
	return false
}
