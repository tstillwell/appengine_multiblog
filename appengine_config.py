"""    This module is used to add any third party libraries to
       the project codebase. See the libs folder and the README file.

       This file is parsed when deploying the application or running the
       local development server.
"""

# appengine_config.py
from google.appengine.ext import vendor

# Add any libraries install in the "libs" folder.
vendor.add('libs')
