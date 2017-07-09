# 3rd Party Code Libraries Directory #

Any third party python code used by the application goes in this directory.

Any third party code __must__ use pure Python code. Python Code with C extensions does not work with App Engine standard environment.

Be sure to test code to make sure it works on Google App Engine before full deployment.

See `appengine_config.py` in the parent directory to see how third party libraries are loaded.

For more information on using third party libraries see

http://cloud.google.com/appengine/docs/standard/python/tools/using-libraries-python-27