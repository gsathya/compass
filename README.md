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
WSGIDaemonProcess yourapplication user=nobody group=nogroup threads=5
WSGIScriptAlias /test/ /path/to/app.wsgi

<Directory /path/to/app>
    WSGIProcessGroup yourapplication
    WSGIApplicationGroup %{GLOBAL}
    Order deny,allow
    Allow from all
</Directory>
```
