Compass
======

This script extract some statistics about relays using aggregate data
based on the current consensus.

Run
===

```
* ./compass.py --download
* ./compass.py
```

Examples:

* To get the top five exit nodes in France:
  ```./compass.py --top=5 --exits-only --country=fr ```
* To get weights of the top ten AS of all relays in Germany:
   ```./compass.py --top=10 --by-as --country=de```

Deploy
====

```
* Install Pip
$ apt-get install python-dev python-pip
* Use requirements.txt to install dependancies
$ pip install -r requirements.txt
```

In case you want to use Apache, 
```
$ cat app.wsgi
#!/usr/bin/python

import os, sys
sys.path.append('/path/to/app')

from app import app as application

$ cat /etc/apache2/sites-available/default
WSGIDaemonProcess compass user=nobody group=compass threads=5
WSGIScriptAlias /compass /srv/compass.torproject.org/compass/app.wsgi

<Directory /srv/compass.torproject.org/compass>
    WSGIProcessGroup compass
    WSGIApplicationGroup %{GLOBAL}
    Order deny,allow
    Allow from all
</Directory>
```

Dependencies
=========

Written and tested on Python 2.6.6/2.7.x
