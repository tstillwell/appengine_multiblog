
# Local Development Server
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
