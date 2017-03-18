import os
import re
import json
import binascii
import hmac
import uuid
import datetime
import logging
import jinja2
import webapp2
from pbkdf2 import PBKDF2
from google.appengine.ext import ndb

# point to jinja template dir
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
                               autoescape=True)  # always autoescape
HOST_NAME = os.environ['HTTP_HOST']  # The current host name of the app


def render_str(template, **params):  # Pass data to templates
    t = JINJA_ENV.get_template(template)
    return t.render(params)


class Handler(webapp2.RequestHandler):
    """ Base Handler Class """
    def write(self, *a, **kw):
        """write data to HTTP response used for render and testing"""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """ Used to inject the info into the templates """
        t = JINJA_ENV.get_template(template)
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


class MainPage(Handler):
    """Defines behavior of get and post requests for main app page"""
    def get(self):
        self.write("Testblog up and running!")


class Post(ndb.Model):
    """ Adds the Post DB table"""
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    posting_user = ndb.StringProperty(required=True)

    def render(self):
        """ Draws all blog post data """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


def blog_key(name='default'):
    """ Generate a blog key used as parent for posts """
    return ndb.Key('blogs', name)


def post_count():
    """ Returns the total number of posts """
    all_posts = ndb.gql("SELECT * FROM Post").fetch(keys_only=True)
    count = len(all_posts)
    return count


class Comment(ndb.Model):
    """ Comments DB Table """
    comment_text = ndb.TextProperty(required=True)
    parent_post_id = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    posting_user = ndb.StringProperty(required=True)

    def render(self):
        """ Draws comments """
        self._render_text = self.comment_text.replace('\n', '<br>')
        return render_str("comment.html", c=self)


def comment_key(name='default'):
    """ Parent key for comments """
    return ndb.Key('comments', name)


class FrontPage(Handler):
    """ Shows the front page/ blogroll """
    def get(self):
        pagecount = ((post_count() / 10) + 1)
        blogroll = ndb.gql("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        if self.user():
            self.render('front.html', blogroll=blogroll, user=self.user(),
                        pagecount=pagecount, page_id=1)
        else:
            self.render('front.html', blogroll=blogroll,
                        pagecount=pagecount, page_id=1)


class FrontPaginate(Handler):
    """ next page/numbered page links containing additonal posts """
    def get(self, page_id):
        page_offset = ((int(page_id) * 10) - 10)
        pagecount = ((post_count() / 10) + 1)
        nextroll = ndb.gql("""SELECT * FROM Post ORDER BY created
                               DESC LIMIT 10 OFFSET %s""" % page_offset)
        if self.user():
            self.render('front.html', blogroll=nextroll, user=self.user(),
                        pagecount=pagecount, page_id=int(page_id))
        else:
            self.render('front.html', blogroll=nextroll,
                        pagecount=pagecount,  page_id=int(page_id))


class NewPost(Handler):
    """ Page for adding new blog posts """
    def get(self):
        if self.user():
            self.render("newpost.html", user=self.user())
        else:
            error = "You must be logged in to post"
            self.render("newpost.html", error=error)

    def post(self):
        """ takes info from forms """
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            """ If data fields present, make new Post and add it to the db """
            if not self.user():
                error = "You must be logged in to post"
                self.render("newpost.html", subject=subject,
                            content=content, error=error)
            else:
                p = Post(parent=blog_key(), subject=subject,
                         content=content, posting_user=self.user())
                p.put()
                self.redirect('/blog/%s' % str(p.key.id()))  # Permalink
                logging.info("New post created : %s", p.key.id())
        else:
            """ If all data fields are not present,
                 report an error and ask for fields again """
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error, user=self.user())


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
            self.render("permalink.html", post=post,
                        comment_roll=comment_roll, user=self.user())
        else:
            error = "You must be logged in to comment"
            self.render("permalink.html", post=post, error=error,
                        comment_roll=comment_roll)

    def post(self, post_id):
        """ For adding comments """
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        comment_text = self.request.get("comment_text")
        parent_post_id = str(post.key.id())  # file the comment under this post
        if self.user() is None:  # If user is not logged in or invalid cookie
            error = "Sorry, you need to be logged in to comment"
            comment_roll = load_comments(post_id)
            self.render("permalink.html", post=post,
                        comment_roll=comment_roll, error=error)
            return
        if comment_text == '':
            error = "Your comment cannot be blank"
            comment_roll = load_comments(post_id)
            self.render("permalink.html", post=post, user=self.user(),
                        comment_roll=comment_roll, error=error)
            return
        c = Comment(parent=comment_key(), comment_text=comment_text,
                    posting_user=self.user(),
                    parent_post_id=parent_post_id)
        c.put()
        comment_roll = load_comments(post_id)
        self.render("permalink.html", post=post, new_comment=c,
                    comment_roll=comment_roll, user=self.user())
        logging.info("New comment added to post [%s] by user: %s",
                     c.parent_post_id, c.posting_user)

""" USER RELATED classes """


class Secret(ndb.Model):
    """HMAC Secret Key stored in datastore"""
    key_string = ndb.StringProperty(required=True)


def secret_key():
    """ Get secret key from datastore. If one does not exist it makes one"""
    secret_check = ndb.gql("SELECT key_string FROM Secret")
    key = secret_check.get()
    if key:  # if key is present return it
        return key.key_string
    else:  # if not make one and return/store it
        new_key = binascii.b2a_hqx(os.urandom(64))  # 64-bits of ASCII
        k = Secret(key_string=new_key)
        k.put()
        logging.critical("A NEW SECRET KEY HAS BEEN CREATED FOR HMAC")
        return new_key

SECRET = secret_key()


class User(ndb.Model):
    """ Adds Users DB Table """
    username = ndb.StringProperty(required=True)
    user_hash = ndb.StringProperty(required=True)
    salt = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    current_session = ndb.StringProperty(required=False)
    session_expires = ndb.DateTimeProperty(required=False)


def user_key(name='default'):
    """ Generate a blog id from the db row """
    return ndb.Key('users', name)


class Login_attempt(ndb.Model):
    """ Keeps track of login attempts for rate limiting """
    ip_addr = ndb.StringProperty(required=True)
    last_attempt = ndb.DateTimeProperty(required=True)
    attempt_count = ndb.IntegerProperty(required=True)


def cookie_hash(value):
    """Use the secret value with HMAC to prevent cookie tampering"""
    hash = hmac.new(SECRET, str(value)).hexdigest()
    hash = str(hash)
    return hash


def valid_user(cookie_str):
    """Returns username after validating the cookie session data"""
    if cookie_str is None:
        return None
    cookie_parts = cookie_str.split("|")
    if len(cookie_parts) != 2:
        return None
    if cookie_parts[1] == cookie_hash(cookie_parts[0]):
        user_query = ndb.gql("""SELECT * FROM User
                             WHERE current_session ='%s'"""
                             % cookie_parts[0])
        current_user = user_query.get()
        if (current_user and
           datetime.datetime.now() < current_user.session_expires):
            current_user.session_expires = (datetime.datetime.now() +
                                            datetime.timedelta(hours=1))
            current_user.put()
            return current_user.username
    else:
        return None


def new_salt():
    """ Generates a 32-bit hex salt for user pw salting """
    salt = binascii.hexlify(os.urandom(32))
    return salt


def hash_password(password, salt):
    """ Hash user pw with PBKDF2 alg with iterations as work factor"""
    hashed_pw_bin = PBKDF2(password, salt, iterations=20000)
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


def login_rate_limit(ip_address):
    check_attempt_query = ndb.gql("""SELECT * FROM Login_attempt
                                      WHERE ip_addr = '%s'""" % ip_address)
    attempted_prev_login = check_attempt_query.get()
    if attempted_prev_login:
        attempts_so_far = attempted_prev_login.attempt_count
        if (attempts_so_far >= 10 and (datetime.datetime.now() <=
           attempted_prev_login.last_attempt + datetime.timedelta(minutes=1))):
                logging.info("IP %s is limited on login attempts", ip_address)
                return 403  # Too many attempts.
        attempted_prev_login.attempt_count += 1
        attempted_prev_login.last_attempt = datetime.datetime.now()
        attempted_prev_login.put()
    else:  # if user has not attempted to login prevoiusly
        attempt = Login_attempt(ip_addr=ip_address,
                                last_attempt=datetime.datetime.now(),
                                attempt_count=1)
        attempt.put()


USER_RE = re.compile(r"^[a-zA-Z0-9-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


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

        params = dict(username=username,
                      email=email)

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

        else:  # check if user exists, if they do prompt a new username
            userquery = ndb.gql("""
             SELECT * FROM User
             WHERE username = '%s'""" % username)
            emailquery = ndb.gql("""
             SELECT * FROM User
             WHERE email = '%s'""" % email)
            user_exists = userquery.get()
            email_exists = emailquery.get()
            if user_exists:
                params['error_taken'] = "Username unavailable."
                self.render('registration.html', **params)
                logging.info("Attempted re-registration for: [%s]" % username)
            elif email_exists:
                params['error_taken'] = "Email address in use."
                self.render('registration.html', **params)
                logging.info("Attempted re-registration for: [%s]" % email)
            else:  # if that user does not exist, add the account to the DB
                salt = new_salt()
                user_hash = hash_password(password, salt)
                current_session = session_uuid()
                session_expires = (datetime.datetime.now() +
                                   datetime.timedelta(hours=1))
                u = User(parent=user_key(), username=username,
                         email=email, user_hash=user_hash,
                         salt=salt, current_session=current_session,
                         session_expires=session_expires)
                u.put()  # Put this person into the db
                self.response.headers.add_header(
                  'Set-Cookie', 'Session= %s|%s Path=/'
                  % (str(u.current_session), (cookie_hash
                     (u.current_session))))
                logging.info("New user account created: %s" % username)
                self.render('welcome.html', user=u.username)


class Welcome(Handler):
    """ Redirect new users here after registering """
    def get(self):
        user = self.user()
        if user:
            self.render('welcome.html', user=user)
        else:
            self.redirect('/login')


class Login(Handler):
    """ Login page """
    def get(self):
        """ Draw the login form ONLY with HTTP GET """
        self.render("login.html")

    def post(self):
        """ When user submits the login form """
        user_ip = self.request.remote_addr
        if login_rate_limit(user_ip) == 403:
            return self.error(403)
        """ Takes login credentials that were input by user """
        input_username = self.request.get("username")
        input_password = self.request.get("password")

        while (valid_username(input_username) and
               valid_password(input_password)):
            userquery = ndb.gql("""
              SELECT * FROM User
              WHERE username =
              '%s'""" % input_username)

            target_user = userquery.get()
            if target_user is None:
                break
            hash_input = hash_password(input_password, target_user.salt)
            if hash_input != target_user.user_hash:  # password mismatch
                break
            target_user.current_session = session_uuid()
            target_user.session_expires = (datetime.datetime.now() +
                                           datetime.timedelta(hours=1))
            target_user.put()

            self.response.headers.add_header(
              'Set-Cookie',
              'Session= %s|%s Path=/'
              % (str(target_user.current_session),
                 (cookie_hash(target_user.current_session))))
            logging.info("Login successful: %s", input_username)
            return self.render('welcome.html', user=target_user.username)

        self.render("login.html", error="Invalid Login")
        logging.info("Login falure: %s", input_username)


class UserPage(Handler):
    """ User summary page shows their recent activity, publicly viewable """
    def get(self, username):
        view_user = ndb.gql("""SELECT * FROM User
                                WHERE username = '%s'""" % username)
        profileUser = view_user.get()
        if not profileUser:
            self.error(404)
            return
        post_roll = ndb.gql("""SELECT * FROM Post WHERE posting_user = '%s'
                                ORDER BY created DESC""" % username)
        if self.user():
            self.render("useractivity.html", view_user=profileUser,
                        post_roll=post_roll, user=self.user())
        else:
            self.render("useractivity.html", view_user=profileUser,
                        post_roll=post_roll)


class UserRSS(Handler):
    """ Renders RSS feed for each user """
    def get(self, username):
        view_user = ndb.gql("""SELECT * FROM User
                                WHERE username = '%s'""" % username)
        profileUser = view_user.get()
        if not profileUser:
            self.error(404)
            return
        post_roll = ndb.gql("""SELECT * FROM Post WHERE posting_user = '%s'
                                ORDER BY created DESC LIMIT 10""" % username)
        self.render("userrss.xml", requested_user=profileUser,
                    blog_roll=post_roll, host=HOST_NAME)


class Manage(Handler):
    """Allows user to edit/delete their own comments & posts"""
    def get(self):
        if self.user():
            post_roll = ndb.gql("""SELECT * FROM Post WHERE posting_user = '%s'
                                    ORDER BY created DESC""" % self.user())
            comment_roll = ndb.gql("""SELECT * FROM Comment WHERE
                                       posting_user = '%s' ORDER BY created
                                       DESC""" % self.user())
            self.render("manage.html", user=self.user(),
                        post_roll=post_roll, comment_roll=comment_roll)
        else:  # If user is not logged in, show an error
            self.error(404)


class EditPost(Handler):
    """ Edit page user gets here from clicking edit on posts from manage"""
    def get(self, post_id):
        """ IF user is the post owner, they can edit the post """
        if self.user():
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if post.posting_user == self.user():
                self.render("edit.html", post=post, user=self.user())
        else:
            self.error(404)

    def post(self, post_id):
        """ If users match and they entered new content, change the post """
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


class EditComment(Handler):
    def get(self, comment_id):
        """ If comment owner matches current user draw comment edit form """
        if self.user():
            key = ndb.Key('Comment', int(comment_id), parent=comment_key())
            comment = key.get()
            if comment.posting_user == self.user():
                self.render("editc.html", comment=comment, user=self.user())
        else:
            self.error(404)

    def post(self, comment_id):
        """ If user matches comment owner, update comment in the datastore """
        if self.user():
            content = self.request.get("content")
            key = ndb.Key('Comment', int(comment_id), parent=comment_key())
            comment = key.get()
            if comment.posting_user == self.user():
                comment.comment_text = content
                comment.put()
                self.redirect('/blog/%s' % str(comment.parent_post_id))
        else:
            self.error(404)


class CommentAjax(Handler):
    """ Read JSON request, validates it, updates client with response """
    def post(self):
        request_data = json.loads(self.request.body)
        target_comment = int(request_data['comment_id'])
        comment_to_update = Comment.get_by_id(target_comment,
                                              parent=comment_key())
        if comment_to_update.posting_user == self.user():
            new_comment_text = (request_data['new_text'])
            comment_to_update.comment_text = new_comment_text
            comment_to_update.put()
            self.response.out.write(json.dumps((
                                    {'new_text': new_comment_text})))


class DeletePost(Handler):
    """Allows a User to permanently and completely delete a post"""
    def get(self, post_id):
        """ If user is the post owner, they can delete the post """
        if self.user():
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if post.posting_user == self.user():
                self.render("delete.html", post=post, user=self.user())
        else:
            self.error(404)

    def post(self, post_id):
        """ If user match and they click delete form, remove the post """
        if self.user():
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if post.posting_user == self.user():
                key.delete()
                self.redirect('/manage')
                logging.info("Post Deleted: %s" % post_id)
        else:
            self.error(404)


class Logout(Handler):
    """Logout Behavior"""
    def get(self):
        if self.cookie():
            user_query = ndb.gql("""SELECT * FROM User WHERE
                                     username = '%s'""" % self.user())
            person = user_query.get()
            # remove session token from DB, invalidating it server side
            person.current_session = ''
            person.session_expires = None
            person.put()
            logging.info("User logged out: %s" % person.username)
        # Reset the cookie value
        self.response.headers.add_header('Set-Cookie', 'Session=')
        self.redirect("/blog")


# Router - Bind these URLs to above Request Handler instances
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', FrontPage),
                               ('/blog/page/([1-9][0-9]*)', FrontPaginate),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)', PermaLink),
                               ('/signup', Signup),
                               ('/welcome', Welcome),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/users/([a-zA-Z0-9-]+)', UserPage),
                               ('/users/([a-zA-Z0-9-]+)/rss', UserRSS),
                               ('/manage', Manage),
                               ('/edit/([0-9]+)', EditPost),
                               ('/edit/c/([0-9]+)', EditComment),
                               ('/delete/([0-9]+)', DeletePost),
                               ('/commentajax/', CommentAjax),
                               ],
                              debug=True,)
