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

* Builtin HTTPS/SSL support.

* Easy account registration.

* Session management via cookies with HMAC signing.

* Users gets their own page and RSS feed containing their posts.

* Users can edit or delete their posts at any time.

* Commenting is built in to the site and does not require external services.

* Uses javascript for visual enhancements but degrades gracefully if users have javascript disabled.

* Easily customizable with css.

* Custom pages and features can be created and existing structure modified using jinja2 templates and simple python.

* Bultin logging.

* Several security features built in to prevent hijacking and abuse.

* Password resets via email.


## Setup Info
If you are unfamiliar with google app engine, it is a Platform as a Service (PaaS) that runs on Google's cloud infrastructure.

App Engine supports multiple languages and build types-
this app uses what is known as the
Python Standard Environment
(as opposed to the flexible environment)

The standard environment uses Python 2.7.9

While deploying the application to app engine works with only
the gcloud command line tool and the code in this repo -
you will probably want to customize it first.


#### Local Development Server
To customize the app and test it locally you first need to have Python 2.7.9 installed

then install the Google Cloud SDK and the App Engine extension for python

To get the SDK follow the guide here:

https://cloud.google.com/appengine/docs/standard/python/download


Once you have the SDK setup, you need the required dependencies
to test the app locally or you will get errors when you try to start the app.

The easiest way to get the dependencies is by using pip
on the requirements.txt file included with this project.

`pip install -r requirements.txt`


Finally, execute dev_appserver.py included with the Google Cloud SDK like so

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

in your browser

And you should see the FrontPage.

From here, make any changes you want to the code and you can preview them in your
browser until you are satisfied.

The initial console message when you start the local development server also shows

`Starting admin server at...`

That is the local development server admin
panel where you can view the contents of the datastore and more.

If you run into errors or the page does not load,
check the console first to see if there is a stack trace
or other error message being logged there.

**WARNING** -

The project behaves functionally the same on the local development server as it does in production on app engine, but unfortunately there are differences between the two environments that might cause different behavior.

If you change the code, be aware that there are differences between testing and production for app engine and just because something works on the local dev server does not mean that it will work in production so feature testing on app engine is recommended whenever adding or changing features to confirm they work when you go live.

The documentaiton for the Local Development Server can be found here

http://cloud.google.com/appengine/docs/standard/python/tools/using-local-server


#### Deployment
Once you are satisfied with your changes and testing, time to deploy the app to gcloud.

There are two steps to uploading the code to production
for the first time.

1. Create a project on Google Cloud Platform

2. Upload project files

The first step is where you choose a free appspot domain name or configure your custom domain

If you use Google's free appspot domain, you get
free SSL and don't have to worry about certificates.

You do have the option to use your own domain or a custom domain

For more info about using a custom domain see

http://cloud.google.com/appengine/docs/standard/python/console/using-custom-domains-and-ssl

To create a project on GCP, log into the Google Cloud Platform console and choose the option to Create a Project-
if you're using appspot domain this is where
you choose your domain name.
The Project ID is the name of your site and cannot be changed once you choose it, so be sure it's the one you want.


The second step involves uploading the code to the project so the app can start handling requests.

There are 3 YAML files that need to be deployed with the command to ensure the app works properly.

The other files are uploaded automatically.



## Extending the Code

#### Backend

##### Request Handlers
The application uses the webapp2 framework. It creates WSGI application instances that map URLs to Request Handlers.

This map is visible in main.py as the 'app' variable and looks like this:

```
 ('/', MainPage),
 ('/blog/?', FrontPage),
 ('/blog/newpost', NewPost),
 ('/blog/([0-9]+)', PermaLink),
 ('/signup', Signup),

```

There are two seperate parts of each value in this map.
 `('/blog/?', FrontPage)`

The values to the left are the URL paths
 `'/blog/?'`

and the values on the right are the class names that handle HTTP requests to those paths.

`FrontPage`

So whenever an HTTP request from a client is received for /blog , an instance of FrontPage is used to generate a response.

```
class FrontPage(Handler):
    def get(self):
		...do stuff...
        if self.user:
           ...do stuff if user is logged in...
        else:
           ...do stuff if user is not logged in...


```

for each class, seperate GET and POST handlers are defined so the app can respond to the requests appropriately.

Using this paradigm, it is simple to add a new part to the URL mapping and build new classes to handle different app functions.

##### User validation

Each request handler class that inherits from `Handler`
can use `self.user` to get the current account from the datastore
and validate that the user is logged in. If the user is not logged
in or has an expired session, then self.user will return `None`.

User actions can also be validated by using
anti cross-site request forgery (CSRF) tokens.

To use anti-CSRF tokens, pass
`token = csrf_token_for_user(username)`
to the template as an argument in the page get handler.

Then, in the jinja template, include the `token` variable
in a hidden html input field inside the html form you want to validate

```  <input type="hidden" name="csrf-token" value="{{token}}"></input>```

To validate the user's anti-CSRF token, just compare
the value of the token received to the value of
`csrf_token_for_user(username)`
in the post handler and ensure they match.

The anti-CSRF tokens are used per session and once
the session is expired or logged out the token is invalidated.

#### Frontend

##### Pages & Templates
HTML pages are created by using self.render() with
the jinja template as the first argument and any variables needed by the templates as the other arguments.

The templates are stored in the *templates* directory of the project and use the Jinja template engine.

For more info on how to use Jinja, see the Jinja documentation here
http://jinja.pocoo.org/docs/2.9/


##### Changing the style & customizing look and feel
The app uses default (uncustomized) Bootstrap hosted on MaxCDN for faster
page load speeds and simple design.

The app also uses jQuery.

You can remove bootstrap and jquery entirely if you want by removing the links
in the `<head>` section of `base.html` and writing your own css.

Keep in mind that if you remove bootstrap then any modals
will have to be replaced/redesigned
 as they will not work without bootstrap.
The same goes for glyphicons that are used throughout the design.

The default CSS is stored in /static/main.css and can be changed or overwritten
to meet your needs.

Google Fonts are also used in the default setup and can also be changed/reconfigured
if you would like to use different fonts, by replacing the link in `base.html`

## Limitations

There are a few limits
of using this app with App Engine.

You should be aware of these limitations and understand
their workarounds and downsides.

#### Platform

The app is designed for Google App Engine.
Because of this, the portability is limited.

Luckily there is a workaround to this lock-in

The app **can be deployed to other platforms** such as AWS
by using AppScale.

AppScale is an open source PaaS which
allows portability of App Engine applications
to different cloud platforms

For more info on AppScale see

http://www.appscale.com

#### Free Tier

App Engine has a a free quota tier that allows applications
to use a certain amount of resources each day at no cost.

If these quotas are exceeded and you do not have billing
enabled on your account, certain parts of the app
will become unusable until the next 24 hour cycle.

If you do have billing enabled understand
that you will be billed by google for usage
that exceeds the free quota.

For more info on these quotas and billing, see

http://cloud.google.com/appengine/quotas

#### Emails

The app uses email to send password reset emails.
The free quota for email sent using App Engine is
**only 10 emails per day**


There are a few workarounds to the low email limit

You may want to look into using a supported third party
mail API which have free quotas which are much higher than
the Google provided mail API.


Here are some documented/supported mail APIs you can choose from:

Mailgun
http://cloud.google.com/appengine/docs/standard/python/mail/mailgun

Mailjet
http://cloud.google.com/appengine/docs/standard/python/mail/mailjet

Sendgrid
http://cloud.google.com/appengine/docs/standard/python/mail/sendgrid

Be aware that emails are not actually sent when using
the local development server by default, although this can be configured.

#### Logging

The app logs events using the python logging library.
Application logs are saved to the
Google Cloud Platform logging interface

The app also logs all GET and POST requests
in addition to any application errors.

To see these logs, visit the logs viewer page

http://console.cloud.google.com/logs

Logging on the free quota tier is limited to a max of 5gb stored
for a max of 7 days. Logs can be exported, but the export limit
is 100mb for free accounts.

Logging for billing enabled accounts is not limited in this way.

For more info on logging for App Engine see

http://cloud.google.com/logging/docs/

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