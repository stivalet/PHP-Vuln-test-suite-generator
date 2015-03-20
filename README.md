# PHP Vulnerability test suite

Collection of vulnerable and fixed PHP synthetic test cases expressing specific flaws.

Key features:
*  

## Prerequisites

* Linux (developed on Ubuntu 14.04)
* Python 3.3.3 or later 

## Instalation

1. A Python installation is needed to run the generator.

> wget http://www.python.org/ftp/python/3.3.5/Python-3.3.5.tar.xz

> tar xJf ./Python-3.3.5.tar.xz

> cd ./Python-3.3.5

> ./configure --prefix=/opt/python3.3

> make && sudo make install

2. If you want to keep Python 2.7:

	1. create a symlink 'py'.

> mkdir ~/bin

> ln -s /opt/python3.3/bin/python3.3 ~/bin/py

	2. and create a bash alias named 'py':

> alias py="/opt/python3.3/bin/python3.3"

## Basic Usage

After the installation, run "py bin/core.py", which will generate vulnerable and non-vulnerable PHP sample files in a directory called "generation_MM-DD-YYY_HHhMMmSS".

* Show command-line flags available
> py bin/core.py -h

* Generate specific type of flaws
> py bin/core.py -f XSS,Injection

* Generate specific type of CWE
> py bin/core.py -c 79,89

## Getting started
See [doc/User_Guide.pdf](doc/User_Guide.pdf) for setup and documentation.

## Discussion

For discussion please send me an email.
