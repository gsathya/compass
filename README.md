Tor relay stats
=========

Show various metrics related to tor relays.

Deploy
====
```
* Install Pip
$ apt-get install python-dev python-pip
* Use requirements.txt to install dependancies
$ pip install -r requirements.txt
* Install foreman
$ gem install foreman
* Use the Procfile to run the app
$ foreman start
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
