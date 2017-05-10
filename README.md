# Multi-User Blog for Google App Engine

#### A responsive blogging engine designed for multiple users

This app is built to allow different users to sign up and easily blog.
It is not walled or gated so **anyone** can sign up
and post directly to the front page out of the box.

It uses Google's App Engine platform and runs on the standard (free) environment
and can be deployed to app engine in less than a mintue.

Navigate to where the project lives on your system in your terminal and run:

`gcloud app deploy app.yaml index.yaml cron.yaml`

If you want to customize and test the app before deploying it to app engine you need to use the App Engine SDK which includes a local development server so you can check your changes locally before pushing the code to production. For more info see the Setup Info section below.

## Features

Builtin HTTPS/SSL support.

Easy account registration.

Session management via cookies with HMAC signing.

Each user gets their own page and RSS feed containing their posts.

The users can edit or delete their posts at any time.

Commenting is built in to the site and does not require external services.

It uses javascript for visual enhancements but degrades gracefully if users have javascript disabled.

The blog is easily customizable with css.

Custom pages and features can be created and existing structure modified using jinja2 templates and simple python.

Several security features built in to prevent hijacking and abuse.

Password resets via email.

## Setup Info
If you are unfamiliar with google app engine, it is a Platform as a Service (PaaS) that runs on Google's cloud infrastructure.

App Engine supports multiple languages and build types- this app uses what is known as the Python Standard Environment (as opposed to the flexible environment)

The standard environment uses Python 2.7

While deploying the application to app engine works with only the gcloud command line tool and the code in this repo, you will probably want to customize it first.

To customize the app and test it locally you first need to have Python 2.7 installed, then install the Google Cloud SDK and the App Engine extension for python

To get the SDK follow the guide here:

https://cloud.google.com/appengine/docs/standard/python/download

There is more general info on Google App engine available here:
https://cloud.google.com/appengine/




## Built with help from

### Google App Engine
http://cloud.google.com/appengine/

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
Copyright 2017 T. Stillwell

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.