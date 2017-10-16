# Multi-User Blog for Google App Engine

#### A responsive blog built for multiple users
___

Easily allow multiple users to sign up and blog.
Registration is not walled or gated so **anyone** can sign up
and post directly to the front page by default.

Uses Google App Engine and runs on the standard (free)
environment and can be deployed to app engine in less than a mintue.

Navigate to where the project lives on your system in your terminal and run:

`gcloud app deploy app.yaml index.yaml cron.yaml`

___

## Features

* Responsive / mobile interface

* Easy account registration

* Users gets their own page and RSS feed containing their posts

* Users may embed images and videos into posts

* Automatic pagination for front page and user pages

* Users can edit or delete their posts at any time

* Builtin commenting

* Noscript fallback / graceful degradation

* Visual customization possible with css and jinja2 templates

* Extensible with jinja2 and python

* No waiting for index building (fast deployment)

* Automatic caching with memcache

* Builtin logging

* CSRF protection

* PBKDF2 server-side password hashing with salting

* Rate limiting for login attempts (Login attack protection)

* Builtin HTTPS/SSL support

* Session management via cookies with HMAC signing

* User Password resets via email

___

## Environment Info
Google App Engine is a Platform as a Service (PaaS)
that runs on Google's cloud infrastructure.

http://cloud.google.com/appengine/

App Engine supports multiple languages and runtimes-
this app uses the
__Python Standard Environment__
(as opposed to the flexible environment)

http://cloud.google.com/appengine/docs/standard/python/

The standard environment uses Python 2.7.9 with a lightweight python runtime.
For an overview of this environment see
http://cloud.google.com/appengine/docs/standard/python/runtime

For more info about environment limitations, see the _Limitations_ section

If you want to customize / test the app before deploying, you will
need to use the App Engine SDK which includes a local development server so you
can simulate App Engine on your system.

#### Local Development Server
To customize the app and test it locally
you need to set up the SDK.
You can either do so using a vagrant box or
by installing the SDK on your system.


###### Vagrant Box
Use a preconfigured vagrant box for Python/App Engine:
https://github.com/rehabstudio/vagrant-python-appengine


###### Installing on your system

You need to have Python 2.7.9 installed.

Then, install the Google Cloud SDK and the App Engine extension for python

To get the SDK follow the guide here:

http://cloud.google.com/appengine/docs/standard/python/download

___

##### Python Dependencies

Once you have the SDK set up, you will need the required
dependencies (python imports) to test the app locally or
you will get errors when you try to start the app.

The easiest way to get the dependencies is by using pip
on the requirements.txt file included with this project.

`pip install -r requirements.txt`

##### Running the server
Finally, execute dev_appserver.py included with the Google Cloud SDK
on the root project folder:

`
python /Google/Cloud SDK/google-cloud-sdk/bin/dev_appserver.py /this_project
`

to get the local development server up and running.

If the local development server started successfully

You should get a message in the console that says

```starting module "default" running at: http://localhost:8080```

Then just go to

`http://localhost:8080`
(or wherever the above console message says the module is started)

in your browser to see the front page.


From here, make any changes you want to the code in the project folder and
then save and preview in the browser until you are satisfied.

When a file is saved or updated, the dev server hot loads
it so you don't have to restart the server manually.

The initial console message when you start the
local development server also shows

`Starting admin server at...`

That is the local development server admin
panel where you can view the contents of the datastore and more.

If you run into errors or the page does not load,
check the SDK console window first to see if there is a stack trace
or other error message being logged there.

The documentation for the Local Development Server can be found here

http://cloud.google.com/appengine/docs/standard/python/tools/using-local-server

**WARNING** -

The app behaves functionally the same on the local development server as it
does in production on app engine, but there are differences
between these environments that might cause different behavior.

If you change the code, be aware that there are differences between testing
and production for app engine and just because something works on the
local dev server does not mean that it will work in production so
feature testing on app engine is recommended whenever adding or
changing features to confirm they work before going live.

The major differences to watch out for here are missing indexes
causing GQL/datastore queries to fail in production
and attempting to use Python code not supported by the standard
environment (typically any code that uses C extensions).


## Contributing

See CONTRIBUTING.md for contribution guidelines.
TLDR: Open a Pull Request on GitHub.

#### Bugs
If you find any bugs please open an issue on github
with any details about the bug.

If possible, please list the steps to reproduce
the bug or what happened when the bug occurred.


## Built with help from

### Google App Engine
http://cloud.google.com/appengine/

### Python
http://www.python.org/

### Jinja
http://jinja.pocoo.org/

### Bootstrap
http://getbootstrap.com

### Glyphicons
http://glyphicons.com

### jQuery
http://jquery.com/

### jScroll
https://github.com/pklauzinski/jscroll
http://jscroll.com/

 jscroll Copyright © 2011-2017, Philip Klauzinski
 Dual licensed under the MIT and GPL Version 2 licenses.
 http://jscroll.com/#license
 http://www.opensource.org/licenses/mit-license.php
 http://www.gnu.org/licenses/gpl-2.0.html

### Python PBKDF2 library
 pbkdf2 - PKCS#5 v2.0 Password-Based Key Derivation
 Copyright (C) 2007-2011 Dwayne C. Litzenberger <dlitz@dlitz.net>

## LICENSE Info
Copyright 2017 Tristan Stillwell

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to
do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
