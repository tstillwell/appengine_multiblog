""" Main application module. Intended for deployment to Google App Engine.

    Built for App Engine Python Standard Environment platform. Uses Python 2.7.
    Controls all backend processing, storage, and backing service setup using
    WSGI application specification. See README file for more info.
    Open Source Project licensed under the MIT License. See LICENSE file.
"""

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
from google.appengine.api import app_identity, mail
from models import (
    Post,
    Comment,
    Secret,
    User,
    AntiCsrfToken,
    ResetToken,
    LoginAttempt,
    JINJA_ENV
)

HOST_NAME = os.environ['HTTP_HOST']  # The current host name of the app


def render_str(template, **params):
    """ Passes data from application into jinja templates to render pages """
    template_page = JINJA_ENV.get_template(template)
    return template_page.render(params)


class Handler(webapp2.RequestHandler):
    """ Base Handler. All request handlers inherit from this.

        Child classes are mapped with URLs into WSGIApplication router.
        Each handler has a "get" and "post" method used to handle different
        HTTP requests with those verbs
    """

    def write(self, *a, **kw):
        """ write data to HTTP response used for render and testing """
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        """ Fills data into the template and writes as response """
        self.write(render_str(template, **kw))

    def cookie(self):
        """ Used by child classes to get the current Session cookie """
        my_cookie = self.request.cookies.get('Session')
        return my_cookie

    @property
    def user(self):
        """ Returns logged-in username or None """
        return valid_user(self.cookie())


class MainPage(Handler):
    """ Defines behavior of http requests to main site index """
    def get(self):
        """ What to display when user visits the homepage """
        self.redirect('/blog')


def blog_key(name='default'):
    """ Generate a blog key used as parent for posts """
    return ndb.Key('blogs', name)


def post_count():
    """ Returns the total number of posts """
    all_posts = ndb.gql("SELECT * FROM Post").fetch(keys_only=True)
    count = len(all_posts)
    return count


def post_count_for_user(username):
    """ Returns total number of posts for given username """
    user_posts = ndb.gql("""SELECT * FROM Post
                             WHERE posting_user = '%s' """
                         % username).fetch(keys_only=True)
    count = len(user_posts)
    return count


def comment_key(name='default'):
    """ Parent key for comments """
    return ndb.Key('comments', name)


class FrontPage(Handler):
    """ Shows the front page/ blogroll """
    def get(self):
        """ Render the front page and pagination links """
        pagecount = ((post_count() / 10) + 1)
        blogroll = ndb.gql("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        if self.user:
            self.render('front.html', blogroll=blogroll, user=self.user,
                        pagecount=pagecount, page_id=1)
        else:
            self.render('front.html', blogroll=blogroll,
                        pagecount=pagecount, page_id=1)


class FrontPaginate(Handler):
    """ next page/numbered page links containing additonal posts for no js """
    def get(self, page_id):
        """ Uses offset to get further pages if user wants to browse older
            blog posts. Note this is only if browser javascript is disabled
        """
        page_offset = ((int(page_id) * 10) - 10)
        pagecount = ((post_count() / 10) + 1)
        nextroll = ndb.gql("""SELECT * FROM Post ORDER BY created
                               DESC LIMIT 10 OFFSET %s""" % page_offset)
        if self.user:
            self.render('front.html', blogroll=nextroll, user=self.user,
                        pagecount=pagecount, page_id=int(page_id))
        else:
            self.render('front.html', blogroll=nextroll,
                        pagecount=pagecount, page_id=int(page_id))


class AutoPager(Handler):
    """ Javascript auto pagination using jscroll to load in next set of
        posts once the user reaches the bottom of Front page
    """
    def get(self, page_id):
        """ Links from autopager - bare html used by jscroll """
        pagecount = ((post_count() / 10) + 1)
        if int(page_id) > pagecount:
            self.render("nextpage.html", no_more_posts=True)
            return
        page_offset = ((int(page_id) * 10) - 10)
        nextroll = ndb.gql("""SELECT * FROM Post ORDER BY created
                               DESC LIMIT 10 OFFSET %s""" % page_offset)
        self.render("nextpage.html", blogroll=nextroll, page_id=int(page_id))


class NewPost(Handler):
    """ Page for adding new blog posts """
    def get(self):
        """ Renders the newpost form with anti-forgery token into the page """
        if self.user:
            self.render("newpost.html", user=self.user,
                        token=csrf_token_for(self.user))
        else:
            error = "You must be logged in to post"
            self.render("newpost.html", error=error)

    def post(self):
        """ Take info from forms, verify the request is not forged or expired
            and add a post to the datastore
        """
        subject = self.request.get("subject")
        content = self.request.get("content")
        csrf_token = self.request.get("csrf-token")
        if subject and content:
            # If data fields present, make new Post and add it to the db
            if not self.user:
                error = "You must be logged in to post"
                self.render("newpost.html", subject=subject,
                            content=content, error=error)
            if self.user and csrf_token == csrf_token_for(self.user):
                blog_post = Post(parent=blog_key(), subject=subject,
                                 content=content, posting_user=self.user)
                blog_post.put()
                self.redirect('/blog/%s' % str(blog_post.key.id()))
                logging.info("New post created : %s", blog_post.key.id())
        else:
            # If all data fields are not present,
            # report an error and ask for fields again
            error = "Subject and Content are both required"
            self.render("newpost.html", subject=subject, content=content,
                        error=error, user=self.user,
                        token=csrf_token_for(self.user))


class PermaLink(Handler):
    """ Page dedicated to one post and associated comments """
    def get(self, post_id):
        """ Make sure the link is valid and show the post with comments """
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        # gets the comments whose post_id matches the post_id of the page
        comment_roll = load_comments(post_id)

        if not post:
            self.error(404)
            return
        if self.user:
            self.render("permalink.html", post=post, user=self.user,
                        comment_roll=comment_roll,
                        token=csrf_token_for(self.user))
        else:
            error = "You must be logged in to comment"
            self.render("permalink.html", post=post, error=error,
                        comment_roll=comment_roll)

    def post(self, post_id):
        """ For adding comments. Verify user is valid and add comment to db """
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        comment_text = self.request.get("comment_text")
        csrf_token = self.request.get("csrf-token")
        parent_post_id = str(post.key.id())  # file the comment under this post
        if self.user is None:  # If user is not logged in or invalid cookie
            error = "Sorry, you need to be logged in to comment"
            comment_roll = load_comments(post_id)
            self.render("permalink.html", post=post,
                        comment_roll=comment_roll, error=error)
            return
        if comment_text == '':
            error = "Your comment cannot be blank"
            comment_roll = load_comments(post_id)
            self.render("permalink.html", post=post, user=self.user,
                        comment_roll=comment_roll, error=error)
            return
        if len(comment_text) > 3000:
            error = "Comment too long, must be less than 3000 characters"
            comment_roll = load_comments(post_id)
            self.render("permalink.html", post=post, user=self.user,
                        comment_roll=comment_roll, error=error)
            return
        if self.user and csrf_token == csrf_token_for(self.user):
            comment = Comment(parent=comment_key(), comment_text=comment_text,
                              posting_user=self.user,
                              parent_post_id=parent_post_id)
            comment.put()
            comment_roll = load_comments(post_id)
            self.render("permalink.html", post=post, user=self.user,
                        comment_roll=comment_roll,
                        token=csrf_token_for(self.user))
            logging.info("New comment added to post [%s] by user: %s",
                         comment.parent_post_id, comment.posting_user)


def secret_key():
    """ Get secret key from datastore.

        Read Secret Key from db. If one does not exist, create one
        and the event gets logged since this is an important security event
    """
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


def user_key(name='default'):
    """ Parent key for user accounts in datastore """
    return ndb.Key('users', name)


def user_by_name(username):
    """ query datastore for username and return user entity if it exists """
    user_query = ndb.gql("""
     SELECT * FROM User
     WHERE username = '%s'""" % username)
    user_entity = user_query.get()
    if user_entity is not None:
        return user_entity
    else:
        return None


def user_by_email(email):
    """ query datastore for user by email and return entity if it exists """
    user_query = ndb.gql("""
     SELECT * FROM User
     WHERE email = '%s'""" % email)
    user_entity = user_query.get()
    if user_entity is not None:
        return user_entity
    else:
        return None


def reset_email(recipient, token):
    """ Sends email containing a password reset link if user requests it """
    app_name = app_identity.get_application_id()
    from_address = ("noreply@%s.appspotmail.com" % app_name)
    if os.environ['HTTPS'] == 'off':
        url_protocol = 'http'
    else:
        url_protocol = 'https'
    body = """
              A password reset request was created for your blog account.
              If you wish to reset your password, please use this link

              %s://%s/resetpassword/%s

              This link is only valid for 15 minutes.""" % (
                  url_protocol, HOST_NAME, token)
    mail.send_mail(sender=from_address, to=recipient,
                   subject="Blog password reset requested", body=body)


def cookie_hash(value):
    """ Use the secret value with HMAC to prevent session forgery/tampering """
    session_digest = str(hmac.new(SECRET, str(value)).hexdigest())
    return session_digest


def valid_user(cookie_str):
    """ Returns username after validating the cookie session data """
    if cookie_str is None:
        return None
    cookie_parts = cookie_str.split("|")
    if len(cookie_parts) != 2:
        return None
    if hmac.compare_digest(str(cookie_parts[1]),
                           str(cookie_hash(cookie_parts[0]))):
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
    """ Generates a salt for user password security """
    salt = binascii.b2a_uu(os.urandom(32))[0:-2]  # trim \n from end of string
    return salt


def hash_password(password, salt):
    """ Hash user pw with PBKDF2 alg with iterations as work factor """
    hashed_pw_bin = PBKDF2(password, salt, iterations=20000)
    hashed_pw = hashed_pw_bin.hexread(32)
    return hashed_pw


def new_hash(user_entity, new_password):
    """ Updates user entity with new salt and hash for new_password """
    salt = new_salt()
    user_hash = hash_password(new_password, salt)
    user_entity.salt = salt
    user_entity.user_hash = user_hash
    user_entity.put()  # add new salt and hash to datastore


def session_uuid():
    """ Make a new UUID for logged-in session tokens """
    new_uuid = str(uuid.uuid4())
    return new_uuid


def new_csrf_token():
    """ Make a synchronizer token for forms to prevent CSRF attacks """
    base_64_string = binascii.b2a_base64(os.urandom(64))
    csrf_token = base_64_string[:-1]  # strip newline character
    return csrf_token


def csrf_token_for(username):
    """ Return the users anti CSRF token to embed in html forms """
    query = ndb.gql("""SELECT * FROM AntiCsrfToken
                       WHERE associated_user = '%s'""" % username)
    csrf_token = query.get()
    return csrf_token.csrf_sync_token


def load_comments(post_id):
    """ Returns all comments associated with specific post """
    comment_query = Comment.query(ancestor=comment_key()).filter(
        Comment.parent_post_id == post_id)
    comments = comment_query.fetch()
    sorted_comments = sorted(comments, key=lambda comment: comment.created,
                             reverse=True)
    return sorted_comments


def login_rate_limit(ip_address):
    """ Prevents repetitive login attacks by limiting logins from one ip """
    check_attempt_query = ndb.gql("""SELECT * FROM LoginAttempt
                                      WHERE ip_addr = '%s'""" % ip_address)
    recent_attempt = check_attempt_query.get()
    if recent_attempt:
        attempts_so_far = recent_attempt.attempt_count
        if (attempts_so_far >= 10 and
                (datetime.datetime.now() <=
                 recent_attempt.last_attempt+datetime.timedelta(minutes=1))):
            logging.info("IP %s is limited on login attempts", ip_address)
            return 403  # Too many attempts.
        recent_attempt.attempt_count += 1
        recent_attempt.last_attempt = datetime.datetime.now()
        recent_attempt.put()
    else:  # if user has not attempted to login prevoiusly
        attempt = LoginAttempt(ip_addr=ip_address,
                               last_attempt=datetime.datetime.now(),
                               attempt_count=1)
        attempt.put()


# validation functions for user signup form
def valid_username(username):
    """ ensure well formed username and return it """
    user_re = re.compile(r"^[a-zA-Z0-9-]{3,20}$")
    return username and user_re.match(username)


def valid_password(password):
    """ ensure password is well formed and return it """
    pass_re = re.compile(r"^.{3,200}$")
    return password and pass_re.match(password)


def valid_email(email):
    """ ensure well formed email address and return it """
    email_re = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    if email_re.match(email):
        return email


def signup_errors(username, password, verify, email):
    """ Returns a list of errors if user has invalid signup inputs """
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
    if have_error is True:
        return params
    if have_error is False:
        return False


def make_account(username, email, password):
    """ Add a new account to the datastore """
    salt = new_salt()
    user_hash = hash_password(password, salt)
    current_session = session_uuid()
    session_expires = (datetime.datetime.now() +
                       datetime.timedelta(hours=1))
    account = User(parent=user_key(), username=username,
                   email=email, user_hash=user_hash,
                   salt=salt, current_session=current_session,
                   session_expires=session_expires)
    account.put()  # Put this person into the db
    anti_forgery_token = AntiCsrfToken(
        associated_user=username,
        csrf_sync_token=new_csrf_token())
    anti_forgery_token.put()
    return account


class Signup(Handler):
    """ Page used for registering new user accounts """
    def get(self):
        """ Draws registration page and forms """
        self.render("registration.html")

    def post(self):
        """ Verify signup inputs are valid and create account """
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        params = dict(username=username, email=email)
        any_signup_errors = signup_errors(username, password, verify, email)
        if any_signup_errors:
            self.render('registration.html', **any_signup_errors)
        else:  # check if user exists, if they do prompt a new username
            user_exists = user_by_name(username)
            email_exists = user_by_email(email)
            if user_exists:
                params['error_taken'] = "Username unavailable."
                self.render('registration.html', **params)
                logging.info("Attempted re-registration for: [%s]", username)
            elif email_exists:
                params['error_taken'] = "Email address in use."
                self.render('registration.html', **params)
                logging.info("Attempted re-registration for: [%s]", email)
            else:  # if that user does not exist, add the account to the DB
                account = make_account(username, email, password)
                self.response.headers.add_header(
                    'Set-Cookie', 'Session= %s|%s Path=/'
                    % (str(account.current_session),
                       (cookie_hash(account.current_session))))
                logging.info("New user account created: %s", username)
                self.render('welcome.html', user=account.username)


class Login(Handler):
    """ Login page """
    def get(self):
        """ Render the login page and form """
        self.render("login.html")

    def post(self):
        """ If the ip address of the user was
            recently rate limited, return an error and stop processing.
            Otherwise verify password hash matches stored hash
        """
        user_ip = self.request.remote_addr
        if login_rate_limit(user_ip) == 403:
            error = "Too many login attempts, please try again later."
            return self.render("login.html", error=error)
        # Takes login credentials that were input by user
        input_username = self.request.get("username")
        input_password = self.request.get("password")

        while (valid_username(input_username) and
               valid_password(input_password)):
            target_user = user_by_name(input_username)
            if target_user is None:
                break
            hash_input = hash_password(input_password, target_user.salt)
            if hash_input != target_user.user_hash:  # password mismatch
                break
            # If user session expired create a new one, otherwise reuse
            if (target_user.session_expires is None or
                    target_user.session_expires < datetime.datetime.now()):
                target_user.current_session = session_uuid()
                csrf_token_query = ndb.gql("""
                           SELECT * FROM AntiCsrfToken WHERE
                           associated_user = '%s'""" % target_user.username)
                users_token = csrf_token_query.get()
                users_token.csrf_sync_token = new_csrf_token()
                users_token.put()  # new csrf token to replace expired one
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
        logging.info("Login failure: %s", input_username)


class ForgotPassword(Handler):
    """ User uses this form to reset their password via email """
    def get(self):
        """ Draw the forgot password page and form """
        self.render('forgotpassword.html')

    def post(self):
        """ Verify the email belongs to a user and send them an email
            with a password reset link
        """
        email = self.request.get("email")
        target_user = user_by_email(email)
        if target_user is None:
            logging.info("Invalid password reset attempt for %s", email)
            error = "No account with that email found"
            self.render('forgotpassword.html', error=error)
            return
        if target_user:
            logging.info("Sending password reset email to %s", email)
            reset_token_uuid = str(uuid.uuid4())
            token_expires = (datetime.datetime.now() +
                             datetime.timedelta(minutes=15))
            acct_email = target_user.email
            token_for_db = ResetToken(associated_acct_email=acct_email,
                                      token_guid=reset_token_uuid,
                                      expires=token_expires)
            token_for_db.put()
            reset_email(acct_email, reset_token_uuid)
            sent_email = True
            self.render("forgotpassword.html", sent_email=sent_email)


class ResetPassword(Handler):
    """ Form to enter new password user gets link in email from forgot form """
    def get(self, reset_token):
        """ Verify link is still valid and draw reset form """
        token_query = ndb.gql("""SELECT * FROM ResetToken
                                 WHERE token_guid = '%s'""" % reset_token)
        token = token_query.get()
        if not token or token.expires < datetime.datetime.now():
            self.write("Invalid or expired reset request")
            return
        else:
            self.render("resetpassword.html")

    def post(self, reset_token):
        """ Verify form inputs and token again and update password """
        new_pass = self.request.get("password")
        new_pass_verify = self.request.get("verify")
        token_query = ndb.gql("""SELECT * FROM ResetToken
                                 WHERE token_guid = '%s'""" % reset_token)
        token = token_query.get()
        if not token or token.expires < datetime.datetime.now():
            self.write("Sorry, the form is expired. Please try again")
            return
        if new_pass != new_pass_verify:
            error = "Passwords did not match. Please try again"
            self.render("resetpassword.html", error=error)
        if not valid_password(new_pass):
            error = "The password you entered is invalid. Please try another"
            self.render("resetpassword.html", error=error)
        if (new_pass == new_pass_verify and valid_password(new_pass) and
                token.expires > datetime.datetime.now()):
            user = user_by_email(token.associated_acct_email)
            new_hash(user, new_pass)
            logging.info("New password created for %s", user.username)
            token.expires = datetime.datetime.now()
            token.put()  # expire reset token so it can't be re-used
            self.render("resetpassword.html", password_udpated=True)


class UpdatePassword(Handler):
    """ Lets logged in users change their password """
    def get(self):
        """ Verify user has a valid session cookie and draw the form """
        if self.user:
            self.render("updatepass.html", user=self.user,
                        token=csrf_token_for(self.user))
        else:
            self.redirect('/login')

    def post(self):
        """ Validate old password and new passwords and update """
        current_pass = self.request.get("currentpassword")
        new_pass = self.request.get("newpassword")
        verify_new = self.request.get("newpassword-confirm")
        csrf_token = self.request.get("csrf-token")
        new_token = csrf_token_for(self.user)  # new token in case bad inputs
        params = dict()
        if self.user is None:
            return self.redirect("/login")
        if (self.user and valid_password(new_pass) and
                verify_new == new_pass and
                csrf_token == csrf_token_for(self.user)):
            user = user_by_name(self.user)
            if user.user_hash != hash_password(current_pass, user.salt):
                wrong_pw = "You did not enter your correct current password"
                self.render("updatepass.html", user=self.user, error=wrong_pw,
                            token=new_token)
                return
            new_hash(user, new_pass)  # update this users password
            new_session = session_uuid()
            session_expires = (datetime.datetime.now() +
                               datetime.timedelta(hours=1))
            user.current_session = new_session  # give user a new session
            user.session_expires = session_expires
            user.put()
            logging.info("Password updated for user: %s", user.username)
            self.response.set_cookie(
                'Session',
                ('%s|%s' % (str(new_session),
                            cookie_hash(new_session))), overwrite=True)
            return self.render("updatepass.html", user=self.user, updated=True)
        if new_pass != verify_new:
            params['error_mismatch'] = "Passwords did not match."
        if not valid_password(new_pass):
            params['error_invalid'] = "New Password is not valid."
        self.render("updatepass.html", user=self.user, token=new_token,
                    **params)


class UserPage(Handler):
    """ User summary page shows their recent activity, publicly viewable """
    def get(self, username):
        """ Make sure the user in the url is valid then show their page """
        profile_user = user_by_name(username)
        if not profile_user:
            self.error(404)
            return
        user_posts = Post.query(ancestor=blog_key()).filter(
            Post.posting_user == username)
        posts = user_posts.fetch()
        sorted_posts = sorted(posts,
                              key=lambda post: post.created, reverse=True)[:10]
        pagecount = ((post_count_for_user(username) / 10) + 1)
        if self.user:
            self.render("useractivity.html", view_user=profile_user,
                        user=self.user, post_roll=sorted_posts,
                        pagecount=pagecount, page_id=1)
        else:
            self.render("useractivity.html", view_user=profile_user,
                        post_roll=sorted_posts, pagecount=pagecount, page_id=1)


class UserPageMorePosts(Handler):
    """ Userpage pagination, when there are many posts by one user """
    def get(self, username, page_id):
        """ Validate username and generate another page with more posts """
        profile_user = user_by_name(username)
        if not profile_user:
            self.error(404)
            return
        page_offset = ((int(page_id) * 10) - 10)
        pagecount = ((post_count_for_user(username) / 10) + 1)
        post_roll = ndb.gql("""SELECT * FROM Post WHERE posting_user = '%s'
                                ORDER BY created DESC LIMIT 10 OFFSET %s"""
                            % (username, page_offset))
        if self.user:
            self.render("useractivity.html", view_user=profile_user,
                        user=self.user, post_roll=post_roll,
                        pagecount=pagecount, page_id=int(page_id))
        else:
            self.render("useractivity.html", view_user=profile_user,
                        post_roll=post_roll, pagecount=pagecount,
                        page_id=int(page_id))


class UserRSS(Handler):
    """ Renders RSS feed for each user """
    def get(self, username):
        """ Make sure the user in url is valid then show their rss feed """
        profile_user = user_by_name(username)
        if not profile_user:
            self.error(404)
            return
        post_roll = ndb.gql("""SELECT * FROM Post WHERE posting_user = '%s'
                                ORDER BY created DESC LIMIT 10""" % username)
        self.render("userrss.xml", requested_user=profile_user,
                    blog_roll=post_roll, host=HOST_NAME)


class Manage(Handler):
    """ Allows user to edit/delete their own comments & posts """
    def get(self):
        """ Verify user is logged in show their manage page """
        if self.user:
            user_posts = Post.query(ancestor=blog_key()).filter(
                Post.posting_user == self.user)
            posts = user_posts.fetch()
            sorted_posts = sorted(posts,
                                  key=lambda post: post.created,
                                  reverse=True)
            user_comments = Comment.query(ancestor=comment_key()).filter(
                Comment.posting_user == self.user)
            comments = user_comments.fetch()
            sorted_comments = sorted(comments,
                                     key=lambda comment: comment.created,
                                     reverse=True)
            self.render("manage.html", user=self.user,
                        post_roll=sorted_posts, comment_roll=sorted_comments)
        else:
            self.redirect('/login')


class EditPost(Handler):
    """ Allows users to edit/update their existing posts """
    def get(self, post_id):
        """ Let user see edit form if they are owner """
        if self.user:
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if post and post.posting_user == self.user:
                return self.render("editpost.html", post=post, user=self.user,
                                   token=csrf_token_for(self.user))
        return self.error(404)

    def post(self, post_id):
        """ If users match post owner change the post in db """
        content = self.request.get("content")
        csrf_token = self.request.get("csrf-token")
        if self.user and csrf_token == csrf_token_for(self.user):
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if post and post.posting_user == self.user:
                post.content = content
                post.put()
                return self.redirect('/blog/%s' % str(post.key.id()))
        return self.error(404)


class EditComment(Handler):
    """ Page used to edit comments when user does not have javascript """
    def get(self, comment_id):
        """ If comment owner matches current user draw comment edit form """
        if self.user:
            key = ndb.Key('Comment', int(comment_id), parent=comment_key())
            comment = key.get()
            if comment and comment.posting_user == self.user:
                return self.render("editcomment.html", comment=comment,
                                   token=csrf_token_for(self.user),
                                   user=self.user)
        return self.error(404)

    def post(self, comment_id):
        """ If user matches comment owner, update comment in the datastore """
        if self.user:
            content = self.request.get("content")
            csrf_token = self.request.get("csrf-token")
            key = ndb.Key('Comment', int(comment_id), parent=comment_key())
            comment = key.get()
            if (comment and comment.posting_user == self.user and
                    csrf_token == csrf_token_for(self.user)):
                comment.comment_text = content
                comment.put()
                return self.redirect('/blog/%s' % str(comment.parent_post_id))
        return self.error(404)


class CommentAjax(Handler):
    """ Read JSON request, validates it, updates client with response """
    def post(self):
        """ Verify user with cookie and csrf token, update comment in datastore
            then send a response with the new comment
            text to load into the DOM
        """
        request_data = json.loads(self.request.body)
        target_comment = int(request_data['comment_id'])
        submitted_csrf_token = request_data['csrf_token']
        comment_to_update = Comment.get_by_id(target_comment,
                                              parent=comment_key())
        if (comment_to_update and comment_to_update.posting_user == self.user
                and submitted_csrf_token == csrf_token_for(self.user)):
            new_comment_text = (request_data['new_text'])
            comment_to_update.comment_text = new_comment_text
            comment_to_update.put()
            self.response.out.write(json.dumps((
                {'new_text': new_comment_text})))


class DeletePost(Handler):
    """ Remove post from datastore if user confirms delete """
    def get(self, post_id):
        """ If user is post owner, show delete form """
        if self.user:
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if post and post.posting_user == self.user:
                return self.render("delete.html", post=post, user=self.user,
                                   token=csrf_token_for(self.user))
        return self.error(404)

    def post(self, post_id):
        """ verify user match and csrf token and delete """
        if self.user:
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            csrf_token = self.request.get("csrf-token")
            actual_csrf_token = csrf_token_for(self.user)
            if (post and post.posting_user == self.user and
                    csrf_token == actual_csrf_token):
                key.delete()
                logging.info("Post Deleted: %s", post_id)
                return self.redirect('/manage')
            return self.error(404)


class Logout(Handler):
    """Logout Behavior"""
    def post(self):
        """ Expire user session in db and remove session info from cookie """
        if self.user:
            logout_user = user_by_name(self.user)
            # remove session token from DB, invalidating it server side
            logout_user.current_session = ''
            logout_user.session_expires = None
            logout_user.put()
            logging.info("User logged out: %s", logout_user.username)
        # Reset the cookie value
        self.response.headers.add_header('Set-Cookie', 'Session=')
        self.redirect("/blog")


#  CRON & maintainance task handlers (see cron.yaml)
class CleanupComments(Handler):
    """ Removes comments from the datastore if parent post has been removed """
    def get(self):
        """ Check every comment and remove if no parent exists """
        all_comments = ndb.gql("SELECT * FROM Comment")
        for comment in all_comments:
            parent_post_key = ndb.Key(
                'Post', int(comment.parent_post_id), parent=blog_key())
            parent_post = parent_post_key.get()
            if parent_post is None:
                comment.key.delete()
        logging.info("Cron job finished: Remove orphaned comments")


class CleanupRateLimiter(Handler):
    """ Remove login rate limiting if IPs haven't attempted recently """
    def get(self):
        """ Remove rate limited addresses if no attempts in 2 hours """
        limited_ips = ndb.gql("SELECT * FROM LoginAttempt")
        for offender in limited_ips:
            if (offender.last_attempt <
                    datetime.datetime.now() - datetime.timedelta(hours=2)):
                offender.key.delete()
        logging.info("Cron job finished: Remove rate-limited IPs")


class PurgeResetTokens(Handler):
    """ Remove reset tokens that have been used or expired """
    def get(self):
        """ Check every token and remove from db if expired """
        reset_tokens = ndb.gql("SELECT * FROM ResetToken")
        for token in reset_tokens:
            if token.expires < datetime.datetime.now():
                token.key.delete()
        logging.info("Cron job finished: Remove old reset tokens")


# Router - Binds URLs to above request handlers
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', FrontPage),
                               ('/blog/page/([1-9][0-9]*)', FrontPaginate),
                               ('/blog/nextpage/([1-9][0-9]*)', AutoPager),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)', PermaLink),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/forgot-password', ForgotPassword),
                               (r'/resetpassword/([a-f\d\-]+)', ResetPassword),
                               ('/logout', Logout),
                               ('/users/([a-zA-Z0-9-]+)', UserPage),
                               ('/users/([a-zA-Z0-9-]+)/page/([1-9][0-9]*)',
                                UserPageMorePosts),
                               ('/users/([a-zA-Z0-9-]+)/rss', UserRSS),
                               ('/manage', Manage),
                               ('/manage/updatepass', UpdatePassword),
                               ('/edit/([0-9]+)', EditPost),
                               ('/edit/c/([0-9]+)', EditComment),
                               ('/delete/([0-9]+)', DeletePost),
                               ('/commentajax/', CommentAjax),
                               ('/tasks/orphan-comments', CleanupComments),
                               ('/tasks/de-ratelimit', CleanupRateLimiter),
                               ('/tasks/old-reset-tokens', PurgeResetTokens),
                               ])
