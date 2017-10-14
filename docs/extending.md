# Extending the Code
This page provides an overview of how the application works and how to add new features and customize the app.


### Backend

#### Request Handlers
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

#### Datastore
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

#### User validation

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


#### Scheduled Tasks (Cron Jobs)

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

#### Indexes

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

#### Pages & Templates
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

#### Changing the style & customizing look and feel
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

#### Changing markup allowed in posts or comments
Users are allowed to use html in their posts so long as
the tags are specified in the `render` functions for posts
and comments in `models.py`. The attributes allowed for those
tags are also specified in those functions. To disallow all html,
just remove the tags and attributes keywords from the `render` and `peek` functions.
To allow more html, add the tags and attributes you will allow
users to use into the corresponding variables.
