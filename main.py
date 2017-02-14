import os
import jinja2
import webapp2
import re
import hmac
import hashlib
import binascii
import uuid
from pbkdf2 import PBKDF2
import time
import datetime
from google.appengine.ext import ndb

# point to jinja template dir
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True) # always autoescape

def render_str(template, **params): # Pass data to templates
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    """ Base Handler Class """
    def write(self, *a, **kw):
        """write data to HTTP response used for render and testing"""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """ Used to inject the info into the templates """
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        """ Fills data into the template and writes as response"""
        self.write(self.render_str(template, **kw))

    def cookie(self):
        """Used by child classes to get the current Session cookie"""
        my_cookie = self.request.cookies.get('Session')
        return my_cookie

    def user(self):
        """Returns logged-in username or None"""
        return valid_user(self.cookie())

class MainPage(Handler): # Main site index Handler
    """Defines behavior of get and post requests for main app page"""
    def get(self):
        self.write("Testblog up and running!")

def blog_key(name = 'default'):
    """ Generate a blog id from the db row """
    return ndb.Key('blogs', name)

class Post(ndb.Model):
    """ Adds the Post DB table"""
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    posting_user = ndb.StringProperty(required = True)

    def render(self):
        """ Draws all blog post data """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Comment(ndb.Model):
    """ Comments DB Table """
    comment_text = ndb.TextProperty(required = True)
    parent_post_id = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    posting_user = ndb.StringProperty(required = True)

    def render(self):
        """ Draws comments """
        self._render_text = self.comment_text.replace('\n', '<br>')
        return render_str("comment.html", c = self)

class FrontPage(Handler):
    """ Shows the front page/ blogroll """
    def get(self):
        blogroll = ndb.gql("select * from Post order by created desc limit 10")
        if self.user():
            self.render('front.html', blogroll = blogroll, user = self.user())
        else:
            self.render('front.html', blogroll = blogroll)

class NewPost(Handler):
    """ Page for adding new blog posts """
    def get(self):
        if self.user():
            self.render("newpost.html", user = self.user())
        else:
            error = "You must be logged in to post"
            self.render("newpost.html", error = error)

    def post(self):
        """ takes info from forms """
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            """ If data fields present, make new Post and add it to the db """
            if not self.user():
                error = "You must be logged in to post"
                self.render("newpost.html",subject = subject, content = content, error = error)
            else:
                p = Post(parent = blog_key(), subject = subject, content = content, posting_user = self.user())
                p.put()
                self.redirect('/blog/%s' % str(p.key.id())) # Redirect to permalink
        else:
            """ If all data fields are not present, report an error and ask for fields again """
            error = "subject and content, please!"
            self.render("newpost.html", subject = subject, content = content, error = error, user = self.user())

class PermaLink(Handler):
    """ For getting existing posts.. """
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        # gets the comments whose post_id matches the post_id of the page
        comment_roll = load_comments(post_id)

        if not post:
            self.error(404)
            return
        if self.user():
            self.render("permalink.html", post = post,
                          comment_roll = comment_roll, user = self.user() )
        else:
            self.render("permalink.html", post = post,
                          comment_roll = comment_roll)

    def post(self, post_id): # For adding comments
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        comment_text = self.request.get("comment_text")
        parent_post_id = str(post.key.id()) # file the comment under this post
        if self.user() == None: # If user is not logged in or invalid cookie
            error = "Sorry, you need to be logged in to comment"
            comment_roll = load_comments(post_id)
            self.render("permalink.html", post = post,
                          comment_roll = comment_roll, error = error)
            return
        c = Comment(comment_text = comment_text,
                     posting_user = self.user(),
                     parent_post_id = parent_post_id)
        c.put()
        comment_roll = load_comments(post_id)
        self.render("permalink.html", post = post, new_comment = c,
                      comment_roll = comment_roll, user = self.user() )

""" USER RELATED classes """
class Secret(ndb.Model):
    """HMAC Secret Key stored in datastore"""
    key_string = ndb.StringProperty(required = True)

def secret_key():
    """ Get secret key from datastore. If one does not exist it makes one"""
    secret_check = ndb.gql("SELECT * FROM Secret") # Check datastore for key
    key = secret_check.get()
    if key: # if key is present return it
        return key.key_string
    else: # if not make one and return/store it
        new_key = binascii.b2a_hqx(os.urandom(64)) # 64-bits converted to Ascii
        k = Secret(key_string = new_key)
        k.put()
        return new_key

secret = secret_key()

class User(ndb.Model):
    """ Adds Users DB Table """
    username = ndb.StringProperty(required = True)
    user_hash = ndb.StringProperty(required = True)
    salt = ndb.StringProperty(required = True)
    email = ndb.StringProperty(required = True)
    current_session = ndb.StringProperty(required = False)
    session_expires = ndb.DateTimeProperty(required = False)

def user_key(name = 'default'):
    """ Generate a blog id from the db row """
    return ndb.Key('users', name)

def cookie_hash(value):
    """Use the secret value with HMAC to prevent cookie tampering"""
    hash = hmac.new(secret, str(value)).hexdigest()
    hash = str(hash)
    return hash

def valid_user(cookie_str):
    """Returns username after validating the cookie session data"""
    if cookie_str == None:
        return None
    cookie_parts = cookie_str.split("|")
    if len(cookie_parts) != 2:
        return None
    if cookie_parts[1] == cookie_hash(cookie_parts[0]):
        user_query = ndb.gql("""SELECT * FROM User
                                     WHERE current_session ='%s'"""
                                     %cookie_parts[0])
        current_user = user_query.get()
        if current_user and datetime.datetime.now() < current_user.session_expires:
            current_user.session_expires = (datetime.datetime.now() +
                                             datetime.timedelta(hours=1))
            current_user.put()
            return current_user.username
    else:
        return None

def new_salt():
	""" Generates a 32-bit hex salt for user pw salting"""
	salt = binascii.hexlify(os.urandom(32))
	return salt

def hash_password(password, salt):
    """ Hash user pw with PBKDF2 alg with iterations as work factor"""
    hashed_pw_bin = PBKDF2(password,salt,iterations=20000)
    hashed_pw = hashed_pw_bin.hexread(32)
    return hashed_pw

def session_uuid():
    """ Make a new UUID for logged-in session tokens """
    new_uuid = uuid.uuid4()
    new_uuid = str(new_uuid)
    return new_uuid

def load_comments(post_id):
    """ Returns all comments associated with specific post """
    comments = ndb.gql("""SELECT * from Comment
                               WHERE parent_post_id = '%s'
                               ORDER BY created DESC""" % post_id)
    return comments

USER_RE = re.compile(r"^[a-zA-Z0-9-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    if EMAIL_RE.match(email):
        return email

class Signup(Handler):
    """ Registering new user accounts """
    def get(self):
        """Draws registration page"""
        self.render("registration.html")
    def post(self):
        """takes new user info from forms"""
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = dict(username = username,
                      email = email)

        have_error = False
        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        if password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        if have_error:
            self.render('registration.html', **params)

        else: # check if user exists, if they do prompt a new username
            userquery = ndb.gql("""
             SELECT * FROM User
             WHERE username = '%s'""" % username)

            user = userquery.get()
            if user:
                params['error_taken'] = "Username unavailable."
                self.render('registration.html', **params)

            else: # if that user does not exist, add the account to the DB
                salt = new_salt()
                user_hash = hash_password(password, salt)
                current_session = session_uuid()
                u = User(parent = user_key(), username = username,
                          email = email, user_hash = user_hash,
                          salt = salt, current_session = current_session)
                u.put() # Put this person into the db
                self.response.headers.add_header(
                  'Set-Cookie', 'Session= %s|%s Path=/'
                   % (str(u.current_session), (cookie_hash
                   (u.current_session))))

                time.sleep(0.1)
                self.redirect('/welcome')

class Welcome(Handler):
    """ Redirect new users here after registering """
    def get(self):
        if self.user():
            self.render('welcome.html', user = self.user())
        else:
            self.redirect('/login')

class Login(Handler):
    """ Login page """
    def get(self):
        """ Draw the login form ONLY with HTTP GET """
        self.render("login.html")
    def post(self):
        """ Takes login credentials that were input by user """
        input_username = self.request.get("username")
        input_password = self.request.get("password")

        while valid_username(input_username) and valid_password(input_password):
            userquery = ndb.gql("""
              SELECT * FROM User
              WHERE username =
              '%s'""" % input_username)

            target_user = userquery.get()
            if target_user == None: break
            hash_input = hash_password(input_password, target_user.salt)
            if hash_input != target_user.user_hash: break # password mismatch
            target_user.current_session = session_uuid()
            target_user.session_expires = (datetime.datetime.now() +
                                             datetime.timedelta(hours=1))
            target_user.put()

            self.response.headers.add_header(
              'Set-Cookie',
              'Session= %s|%s Path=/'
              % (str(target_user.current_session),
              (cookie_hash(
              target_user.current_session))))

            time.sleep(0.5)# Give the client a moment to set cookie
            return self.redirect('/welcome')

        self.render("login.html", error = "Invalid Login")

class UserPage(Handler):
    """ User summary page shows their recent activity, publicly viewable """
    def get(self, username):
        view_user = ndb.gql("select * from User where username = '%s'" % username)
        profileUser = view_user.get()
        if not profileUser:
            self.error(404)
            return
        post_roll = ndb.gql("select * from Post where posting_user = '%s' Order By created DESC" % username)
        if self.user():
            self.render("useractivity.html" , view_user=profileUser, post_roll = post_roll, user = self.user())
        else:
            self.render("useractivity.html" , view_user=profileUser, post_roll = post_roll)

class Manage(Handler):
    """Allows user to edit/delete their own comments & posts"""
    def get(self):
        if self.user():
            post_roll = ndb.gql("SELECT * FROM Post WHERE posting_user = '%s' ORDER BY created DESC" % self.user())
            comment_roll = ndb.gql("SELECT * FROM Comment WHERE posting_user = '%s' ORDER BY created DESC" % self.user())
            self.render("manage.html", user = self.user(), post_roll = post_roll, comment_roll = comment_roll)
        else: # If user is not logged in, show an error
            self.error(404) # TODO: Change this to error showing must be logged in to manage

class EditPost(Handler):
    """ Edit page user gets here from clicking edit on posts from manage"""
    def get(self, post_id):
        if self.user():
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if post.posting_user == self.user():
                self.render("edit.html", post = post, user = self.user())
        else:
            self.error(404)

    def post(self, post_id): # TODO: code is duplicated here. Can we do better?
        content = self.request.get("content")
        if self.user():
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if post.posting_user == self.user():
                post.content = content
                post.put()
                self.redirect('/blog/%s' % str(post.key.id()))
        else:
            self.error(404)

class DeletePost(Handler):
    """Allows a User to permanently and completely delete a post"""
    def get(self, post_id):
        if self.user():
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if post.posting_user == self.user():
                self.render("delete.html", post = post, user = self.user())
        else:
            self.error(404)

    def post(self, post_id):
        if self.user():
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if post.posting_user == self.user():
                key.delete()
                time.sleep(0.1)
                self.redirect('/manage')
        else:
            self.error(404)

class Logout(Handler):
    """Logout Behavior"""
    def get(self):
        if self.cookie():
            user_query = ndb.gql("SELECT * FROM User WHERE username = '%s'" % self.user())
            person = user_query.get()
            # remove session token from DB, invalidating it server side
            person.current_session = ''
            person.put()
        # Reset the cookie value
        self.response.headers.add_header('Set-Cookie', 'Session=')
        self.redirect("/blog")


# Router - Bind these URLs to above Request Handler instances
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', FrontPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)', PermaLink),
                               ('/signup', Signup),
                               ('/welcome', Welcome),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/users/([a-zA-Z0-9-]+)', UserPage),
                               ('/manage', Manage),
                               ('/edit/([0-9]+)', EditPost),
                               ('/delete/([0-9]+)', DeletePost),
                               ],
                              debug=True,)
