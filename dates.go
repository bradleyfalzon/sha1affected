package main

import "time"

func getDates() (dateJan2016, dateJun2016, dateJan2017 time.Time, err error) {

	dateJan2016, err = time.Parse("2006-01-02", "2016-01-01")
	if err != nil {
		return
	}

	dateJun2016, err = time.Parse("2006-01-02", "2016-06-01")
	if err != nil {
		return
	}

	dateJan2017, err = time.Parse("2006-01-02", "2017-01-01")
	if err != nil {
		return
	}

	return
}

func equalOrAfter(t1, t2 time.Time) bool {
	return t1.After(t2) || t1.Equal(t2)
}
