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



## Deployment
Once you are satisfied with any changes and testing,
it's time to deploy the app to gcloud.

There are two steps to deploying the app
for the first time.

1. Create a project on Google Cloud Platform

2. Upload project files

The first step is where you can specify a domain:
either choose a free appspot domain name
or configure your own custom domain

If you choose to use Google's free appspot domain,
you get SSL builtin and don't have to worry about certificates.

For more info about using a custom domain see

http://cloud.google.com/appengine/docs/standard/python/console/using-custom-domains-and-ssl

Login to Google Cloud Platform console

http://console.cloud.google.com

Then, go to the projects page and create a new project.


> **If you're using a free appspot domain: **
> The Project ID is the name of your site and cannot be changed
> once you choose it, so be sure it's the one you want.

> Your domain will look something like this:
> `project-name.appspot.com`
> If project-name is already taken, some letters/numbers
> are added to the name to make it unique
> but the page will tell you if this is the case.

Once the project has been created you
need to tell the gcloud tool which project to use
for deployment. To do this run `gcloud init`
and the tool will walk you through selecting the
newly created project.


The second step involves uploading the code to the project
so the app can start handling requests.

There are 3 YAML files that need to be supplied with the
deploy command to ensure the app works properly.

From the project directory you can run

`gcloud app deploy app.yaml index.yaml cron.yaml`

The other code files are uploaded automatically when
`app.yaml` is parsed by the gcloud tool.

For more info on how app.yaml works
See the `app.yaml` reference here:
http://cloud.google.com/appengine/docs/standard/python/config/appref

Once the deploy command finishes, the app is
serving requests and is up and running!


You should now be able to visit your site and see the front page.

You can then use the google cloud console to manage and monitor the application.



## Extending the Code

#### Backend

##### Request Handlers
The application uses the webapp2 framework.
See the documentation for webapp2 here:

http://webapp2.readthedocs.io/en/latest/

It creates WSGI application instances that map URLs to Request Handlers.

This map is visible in main.py as the 'app' variable and looks like this:

```
 ('/', MainPage),
 ('/blog/?', FrontPage),
 ('/blog/newpost', NewPost),
 ('/blog/([0-9]+)', PermaLink),
 ('/signup', Signup),

```

There are two separate parts of each value in this map.
 `('/blog/?', FrontPage)`

The values to the left are the URL paths
 `'/blog/?'`
and are written as regular expressions

and the values on the right are the class names
that handle HTTP requests to those paths.

`FrontPage`

So whenever an HTTP request from a client is received for /blog ,
an instance of FrontPage is used to generate a response.

```
class FrontPage(Handler):
    def get(self):
		...do stuff...
        if self.user:
           ...do stuff if user is logged in...
        else:
           ...do stuff if user is not logged in...


```

for each class, separate GET and POST handlers are defined
so the app can respond to the requests appropriately.

For more info on webapp2s routing see
http://webapp2.readthedocs.io/en/latest/guide/routing.html

Using this paradigm, new routes and new classes to
handle different app functions can be built.

##### Datastore
App Engine's default data storage option
is Google Cloud Datastore.

Cloud datastore is a managed NoSQL database
it **is not a relational database**.

Access to the Datastore is facilitated using the
Python NDB client library.

This app sets up the datastore using `models.py`
The data's structure is configured there.

Data queries for the app are made using
GQL, a SQL-like language used for Cloud Datastore.

Datastore queries do not typically have strong consistency,
so data can sometimes be stale if it was recently modified.
Since this is not a major concern for a blogging app,
you probably don't need to worry about consistency.

If you attempt to add new features that depend
on strong consistency you may see issues.
Strong consistency is possible with
the right data and query structure.

For more info on Datastore see
http://cloud.google.com/appengine/docs/standard/python/datastore/

##### User validation

Each request handler class that inherits from `Handler`
can use `self.user` to get the current account from the datastore
and validate that the user is logged in. If the user is not logged
in or has an expired session, then self.user will return `None`.

User verification is achieved with HTTP cookies after
a user logs in to their account.
The cookies use a session variable that is stored
in the datastore and linked to the account.

Every time a user performs an HTTP interaction
with the server their session is validated
by checking that their cookie data is correctly
associated with the account in the datastore.

The cookies also have anti-tamper functionality
by signing them with a secret key which is
stored in the datastore.

User form submissions can be validated by using
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


##### Scheduled Tasks (Cron Jobs)

Automatically scheduled tasks use the Cron interface
that is built into App Engine. To see the cron jobs
that are used, see the `cron.yaml` file.

The file contains a URL, schedule, and description for each task.

The URLs are normal requests handlers defined just like
other request handlers. Because of this, urls have to be protected
so users can't just run the cron jobs by visiting the URL.
This can be achieved by requiring authorization for those URLs.

For this app,
any urls that are in `/tasks/` are automatically protected by
the `app.yaml` configuration so if new cron jobs are created,
it's best to put them there.

Furthermore, cron jobs on the local development server don't run on schedule
but can be started manually at any time by using
the admin interface to test them.


For more info on creating cron jobs see
http://cloud.google.com/appengine/docs/standard/python/config/cron

#### Backups

You can automatically backup the app data (users, posts, comments, etc...)
by using cron jobs and a Google Cloud storage bucket.

For more info on creating automatic backups, see:

http://cloud.google.com/appengine/articles/scheduled_backups

##### Indexes

Normally, app engine applications that use the datastore require indexes
to be built. The indexes are used to make datastore queries more efficient.

Since this app does not make very complicated queries,
you don't have to wait for indexes to be built before it
starts serving requests, simplifying deployment.

Be mindful, however, when adding new datastore interactions-
they will automatically create indexes and work without hiccups on
the local development server, but queries may fail when deployed
if indexes have not been built yet on Google Cloud Platform.

Indexes are created automatically in `index.yaml` by the local
development server so as long as you exercise the development datastore by
performing new query types before deployment then the indexes will be updated.

For more info regarding index configuration, see

http://cloud.google.com/appengine/docs/standard/python/config/indexconfig

#### Frontend

##### Pages & Templates
HTML pages are created by using self.render() with
the jinja template as the first argument and any variables needed
by the templates as the other arguments.

The templates are stored in the *templates* directory of the
project and use the Jinja template engine.

For more info on how to use Jinja, see the Jinja documentation here
http://jinja.pocoo.org/docs/2.9/

Most page templates use the template base file `base.html`
in the templates directory.

To make a new page with the same structure as the others, use
```{% extends "base.html" %}```
at the beginning of the template
and
```{% endblock %}```
at the end.

Similarly, if you want to change the html page title,
you can use

```{% block title %} Example Title{% endblock %}```

in the template to give that page a custom title,
or omit that to keep the generic title defined in base.html

##### Changing the style & customizing look and feel
The app uses default (uncustomized) Bootstrap hosted on MaxCDN for faster
page load speeds and simple design.

The app also uses jQuery.

You can remove bootstrap and jquery entirely by removing the links
in the `<head>` section of `base.html` and writing your own css.

Keep in mind that if you remove bootstrap then any modals
will have to be replaced/redesigned
as they will not work without bootstrap.
The same goes for glyphicons that are used throughout the design.

The default CSS is stored in /static/main.css and can be changed or overwritten.

Keep in mind that `base.html` actually links to a minified
version of `main.css` so if you change `main.css` no style changes
will happen unless you re-minify the file as main.min.css or change
the link in `base.html` to link directly to `main.css`

Google Fonts are also used in the default setup and can also be changed
if you would like to use different fonts, by replacing the link in `base.html`

## Limitations

There are a few limits
of using this app with App Engine.

You should be aware of these limitations and understand
their workarounds and downsides.

#### Platform

The app is designed for Google App Engine.
Because of this, the portability is limited.
If you try to run the code without app Engine,
it will not work because there is no API.

Luckily there is a workaround to this lock-in

The app **can be deployed to other platforms**
such as AWS (or even self hosted)
by using AppScale.

AppScale is an open source PaaS which
allows portability of App Engine applications
to different cloud platforms

For more info on AppScale see

http://www.appscale.com

App Engine Standard Environment uses a lightweight version of the
Python runtime which only supports a subset of the language.
If you want to use Python 3 or have access to more language features
and libraries, consider using the Flexible Environment as it iess restrictive.

3rd party python libraries are supported, as long as
they are pure python and do not use C extensions.

For more info about using third-party libraries see:

http://cloud.google.com/appengine/docs/standard/python/tools/using-libraries-python-27

#### Free Tier

App Engine has a free quota tier that allows applications
to use a certain amount of resources each day at no cost.

If these quotas are exceeded and you do not have billing
enabled on your account, certain parts of the app
will become unusable until the next 24 hour cycle.

There are also Safety limits in place (DOS proteciton)
on Google App Engine. These are short-term quotas
that apply for free and billing-enabled accounts.


If you do have billing enabled understand
that you will be billed by google for usage
that exceeds the free quota.

For more info on these quotas and billing, see

http://cloud.google.com/appengine/quotas

#### No User Restriction
The way this app is designed is to allow any user to
create an account allowing them to post.

If you want to restrict the users who can create posts and add comments,
you will need to change the way the user registration functionality works
such as by using authorization features of App Engine.

#### Admin Interface
Instead of using a custom admin interface, this app is intended
to be administrated by using App Engine's built in admin console interface.
On App Engine, this functionality is available from google cloud by accessing

http://console.cloud.google.com

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

For more info on email with App Engine see
http://cloud.google.com/appengine/docs/standard/python/mail/

#### Logging

The app logs events using the python logging library.
The logging library is enhanced for App Engine.

Logs for the development server are printed
to the console where `dev_appserver.py` was started.

Application logs in production are saved to the
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

#### Offline Testing
The app uses CDN hosted jQuery and Bootstrap along with Google Fonts.

If you want to test the app offline
you will need to host Bootstrap and jQuery locally
and link to them in the base.html template.

The latest version of Bootstrap can be downloaded here:
http://github.com/twbs/bootstrap/releases/latest

The latest version of jQuery can be downloaded here:
http://jquery.com/download/

The fonts will use a local fallback so keep that in mind when testing offline.

#### Post/Comment User Markup

Users are only allowed to use certain html inside their posts and comments. This is specified in the render functions in `models.py` in the `bleach.clean()` function as the `tags` and `attributes` keyword arguments. Any html not specified there is escaped and will not function as markup.


#### Terms & Conditions and Privacy Policy
If you use this app for the public or commerically,
you should have a terms and conditions and
privacy policy available to protect yourself or
your organization, and notify users
what you are doing with their data.

It is advised that you have these pages created as
separate top level URLs and that you link to them in the footer.

There are no terms of service or privacy policy templates
provided with this app, since these are normally
presented as simple undecorated text.

Consult with a legal professional for more info.

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
Copyright 2017 T. Stillwell

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
