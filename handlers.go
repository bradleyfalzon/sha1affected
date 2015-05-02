package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
)

func homepageHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		errorHandler(w, r, http.StatusNotFound, nil)
		return
	}

	err := templates.ExecuteTemplate(w, "homepage.tmpl", nil)
	if err != nil {
		log.Println("Error executing template homepage: ", err)
	}

}

func resultsHandler(w http.ResponseWriter, r *http.Request) {

	if len(r.URL.Query()["server"]) == 0 {
		errorHandler(w, r, http.StatusBadRequest, errors.New("server not set"))
		return
	}
	serverName := r.URL.Query()["server"][0]

	log.Println("Received request for serverName:", serverName)

	host, err := parseServerName(serverName)
	if err != nil {
		errorHandler(w, r, http.StatusBadRequest, err)
		return
	}

	exceeded, err := checkRateLimit(host)
	if err != nil {
		errorHandler(w, r, http.StatusInternalServerError, err)
		return
	}

	if exceeded {
		errorHandler(w, r, 429, errors.New("Rate limit exceeded for: "+serverName))
		return
	}

	affected, err := checkServer(host)
	if err != nil {
		errorHandler(w, r, http.StatusBadRequest, fmt.Errorf("Error checking %s: %s", host, err))
		return
	}

	page := ResultsPage{
		PageTitle:  serverName,
		ServerName: serverName,
		Affected:   affected,
	}

	err = templates.ExecuteTemplate(w, "results.tmpl", page)
	if err != nil {
		log.Println("Error executing template homepage: ", err)
	}
}

func errorHandler(w http.ResponseWriter, r *http.Request, status int, err error) {
	w.WriteHeader(status)
	switch status {
	case http.StatusNotFound:
		fmt.Fprint(w, "Page Not Found")
		return
	default:
		log.Println(err)
	}

	page := ErrorPage{
		PageTitle: "Error",
		Err:       err,
	}

	err = templates.ExecuteTemplate(w, "error.tmpl", page)
	if err != nil {
		log.Println("Error executing template error: ", err)
	}
}
