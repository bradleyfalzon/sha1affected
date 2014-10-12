SHA1 Affected
============

Checks whether a TLS connection uses SHA1 signed certificates, and if Google Chrome will raise warnings in near future
versions.

Usage
=====

An online checker available at [sha1affected.com](http://sha1affected.com).

Alternatively you can run this yourself (assuming you have Git and Go already installed)
    # git clone https://github.com/bradleyfalzon/sha1affected.git
    # cd sha1affected
    # go build
    # ./sha1affected

This method will start the web server on port 3000 (use ```-port``` parameter to change this), and can also check a single host with
the ```-connect``` parameter.
