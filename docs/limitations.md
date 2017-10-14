
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