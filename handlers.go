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

	log.Println("Got request")
}

func resultsHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("Got request to results")

	if len(r.URL.Query()["server"]) == 0 {
		errorHandler(w, r, http.StatusBadRequest, errors.New("server not set"))
		return
	}
	serverName := r.URL.Query()["server"][0]

	affected, err := checkServer(serverName)
	if err != nil {
		errorHandler(w, r, http.StatusInternalServerError, err)
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
	log.Println("Got error:", err)
	switch status {
	case http.StatusNotFound:
		fmt.Fprint(w, "Page Not Found")
	default:
		fmt.Fprint(w, err)
	}
}
