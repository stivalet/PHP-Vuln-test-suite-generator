# PHP Vulnerability test suite Generator

The PHP synthetic test cases generator produces vulnerable and fixed PHP synthetic test cases expressing specific flaws.

## Prerequisites

* Linux (developed on Ubuntu 14.04)
* Python 3.3.3 or later 

## Installation

A Python installation is needed to run the generator.

> wget http://www.python.org/ftp/python/3.3.5/Python-3.3.5.tar.xz

> tar xJf ./Python-3.3.5.tar.xz

> cd ./Python-3.3.5

> ./configure --prefix=/opt/python3.3

> make && sudo make install

If you want to keep Python 2.7:

1. create a symlink 'py'.

> mkdir ~/bin

> ln -s /opt/python3.3/bin/python3.3 ~/bin/py

2. and create a bash alias named 'py':

> alias py="/opt/python3.3/bin/python3.3"

## Basic Usage

Those commands will generate vulnerable and non-vulnerable PHP sample files in a directory called "PHPTestSuite_MM-DD-YYYY_HHhMMmSS".

> cd PHP-Vulnerability-test-suite/

> cd bin/

> py core.py

## Usage Examples

* Show command-line flags available
> py core.py -h

* Generate specific type of flaws
> py core.py -f XSS,Injection
> py core.py --flaw=IDOR

* Generate specific type of CWE
> py core.py -c 79
> py core.py --cwe=78,89,90,91

## Available Generation

CWEs (-c option)
* 78 : Command OS Injection
* 79 : XSS
* 89 : SQL Injection
* 90 : LDAP Injection
* 91 : XPath Injection
* 95 : Code Injection
* 98 : File Injection
* 209 : Information Exposure Through an Error Message
* 311 : Missing Encryption of Sensitive Data
* 327 : Use of a Broken or Risky Cryptographic Algorithm
* 601 : URL Redirection to Untrusted Site
* 862 : Insecure Direct Object References

OWASP (-f option)
* XSS  : Cross-site Scripting
* IDOR : Insecure Direct Object Reference
* Injection : Injection (SQL, LDAP, XPATH, OS Command, Code)
* URF : URL Redirects and Forwards
* SM : Security Misconfiguration
* SDE : Sensitive Data Exposure

## Getting started
See [doc/User_Guide.pdf](doc/User_Guide.pdf) for setup and documentation.

## Discussion

For discussion please send me an email at: Bertrand 'dot' STIVALET 'at' gmail.com
