PHP-Vulnerability-test-suite
============================

Collection of vulnerable and fixed PHP synthetic test cases expressing specific flaws.

INSTALLATION AND USAGE
----------------------
A Python installation is needed to run the generator. It can be found here : http://www.python.org/download/ (Python 3.3.3 or later).

##Download and compile Python:
> wget http://www.python.org/ftp/python/3.3.5/Python-3.3.5.tar.xz

> tar xJf ./Python-3.3.5.tar.xz

> cd ./Python-3.3.5

> ./configure --prefix=/opt/python3.3

> make && sudo make install

##If you want to keep Python 2.7.*
##Creating a symlink 'py':
> mkdir ~/bin

> ln -s /opt/python3.3/bin/python3.3 ~/bin/py

##Creating bash alias named 'py':
> alias py="/opt/python3.3/bin/python3.3"

After the installation, run "py generator.py", which will generate the samples in a directory called "generation".
Generation directory will be created in the same directory where the generator.py file is.
