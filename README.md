SHA1 Affected
============

Checks whether a TLS connection uses SHA1 signed certificates, and if Google Chrome will raise warnings in near future
versions.

Note: the quality of this code is questionable, and serves only as a warning to others.

Usage
=====

An online checker available at [sha1affected.com](http://sha1affected.com).

Alternatively you can run this yourself (assuming you have Git and Go already installed):

```bash
# git clone https://github.com/bradleyfalzon/sha1affected.git
# cd sha1affected
# go build
# ./sha1affected
```

Default behaviour will start the web server on port 3000 (use ```-port``` parameter to change this). You can also check
a single host without starting the web server using the the ```-connect``` parameter.

```bash
# ./sha1affected <- start web server on port 3000
# ./sha1affected -port 80 <- start web server on port 80
# ./sha1affected -connect yahoo.com <- check server yahoo.com
# ./sha1affected -connect yahoo.com:443 <- optionally specify a port to connect to
```
