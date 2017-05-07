import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'harte'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def render_post(response, post):
        response.out.write('<b>' + post.subject + '</b><br>')
        response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Good afternoon, panda')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    """creation of comment entities"""
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

  
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)
    
    #Returns a post by its id
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = blog_key)

class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order  by created desc limit 10")
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user:
            user_id = self.user.key().id()
            likedpost = db.GqlQuery(
                "select * from Like where ancestor is :1 and user_id = :2",
                key, user_id)
            liked = likedpost.get()
        else:
            liked = None

        if not post:
            self.error(404)
            return
 
        self.render("permalink.html", user=self.user, post = post, liked = liked)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/blog/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog/signup')

class LikeHandler(BlogHandler):
    def get(self, post_id):
        """ If the user is signed in and has authored the post render the
        basetemplate with an error message as they can't like their own posts.
        Pass the user to the sign in page if the user isn't signed in.
        Lookup whether the user has liked the post.  If liked, redirect the user
        to the post page.  Otherwise a new like can be recorded in the db and
        increment the like_count in the post model. """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post is not None:
            user_id = self.user.key().id()
            post_id = post.key().id()

            liked = LikeModel.all().filter(
                'user_id =', user_id).filter('post_id =', post_id).get()

            if liked:
                return self.redirect('/blog/' + str(post.key().id()))

            else:
                like = LikeModel(parent=postkey,
                                 user_id=self.user.key().id(),
                                 post_id=post.key().id())

                post.like_count += 1

                like.put()
                post.put()

                return self.redirect('/blog/' + str(post.key().id()))

class UnlikeHandler(BlogHandler):
    def get(self, post_id):
        """ If the user is signed in and has authored the post render the
        basetemplate with an error message as they can't unlike their own posts.
        Pass the user to the sign in page if the user isn't signed in.
        Lookup whether the user has liked the post.  If liked, delete the like
        from the db and deincrement the like_count in the post model """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post is not None:
            user_id = self.user.key().id()
            post_id = post.key().id()

            l = LikeModel.all().filter(
                'user_id =', user_id).filter('post_id =', post_id).get()

            if l:
                l.delete()
                post.like_count -= 1
                post.put()

                return self.redirect('/' + str(post.key().id()))
            else:
                self.redirect('/blog/' + str(post.key().id()))

class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created_at = db.DateTimeProperty(auto_now_add=True)
    updated_at = db.DateTimeProperty(auto_now=True)
    
"""
    Handles Requests for Comments
"""
class CreateComment(BlogHandler):

    """If user isn't signed in return user to the login page, otherwise render
    the create-comment.html template. """
    def get(self, post_id, user_id):
        if not self.user:
            self.render('/login')
        else:
            self.render("create-comment.html", post_id=post_id)

    """If user isn't signed in return user to the login page, otherwise create
    the comment in the db and redirect to the post page. """
    def post(self, post_id, user_id):
        if not self.user:
            return self.redirect('/login')

        content = self.request.get('content')
        user_name = self.user.name
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(postkey)
        c = Comment(parent=postkey, user=self.user.key(),
                    content=content, post=postkey)
        
        if post:
            c.put()
            post.put()

        self.redirect('/blog/' + post_id)

#Comment entity with content and author properties
class Comment(db.Model):
    content = db.TextProperty(required=True)
    post = db.ReferenceProperty(Post, required=True)
    created_at = db.DateTimeProperty(auto_now_add=True)
    updated_at = db.DateTimeProperty(auto_now=True)
    user = db.ReferenceProperty(User, required=True)

    def format_content(self):
        """ Display comment content in the show_comment.html template. Linebreaks
        will be replaced with a <br> """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('showcomment.html', c=self)

class EditPost(BlogHandler):
    def get(self, post_id):
        """ If the user is signed in and authored the post - render the
        edit-post.html template.  Users that are not signed in are redirected to
        the login page. Otherwise the user does not have permission to edit the
        post. """
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(postkey)

        if post is not None:
            self.render("editpost.html", subject=post.subject,
            content=post.content, post_id=post_id)

            if not self.user:
                return self.redirect("/login")

            else:
                self.write("You do not have permission to edit this post")
                
    def post(self, post_id):
        """ If the user is signed in and authored the post - update the post in the
        db with the new content.  Users that are not signed in are redirected to
        the login page. Otherwise the user does not have permission to edit
        the post. """
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(postkey)

        if post is not None:
            postcontent = self.request.get('content')
            postsubject = self.request.get('subject')

            if postcontent and postsubject:
                post.content = postcontent
                post.subject = postsubject

                post.put()

                self.redirect('/blog/%s' % str(post.key().id()))

            else:
                error_msg = "You do not have permission to edit this post"
                self.render("editpost.html", subject=postsubject,
                            content=postcontent, error=error_msg)

            if not self.user:
                return self.redirect("/login")

            else:
                self.write("You do not have permission to edit this post")

def delete_dependents(comments, likes):
        if comments:
            for c in comments:
                c.delete()
        if likes:
            for l in likes:
                l.delete()
                

class DeletePost(BlogHandler):
    def get(self, post_id, post_user_id):
        """ If the user is signed in and authored the post, delete the post and
        redirect the user to the homepage.  Otherwise, send non-signed in users
        to the login page. For all other cases go back to the current page with
        a permission error. """
        if self.user and self.user.key().id() == int(post_user_id):
            postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(postkey)
            comments = Comment.all().filter('post =', postkey)
            likes = Like.all().filter('post_id =', post.key().id())

            if post:
                delete_dependents(comments=comments, likes=likes)
                post.delete()
                return self.redirect('/blog/')

        elif not self.user:
            return self.redirect("/login")

        else:
            postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(postkey)
            error_msg = "You do not have permission to delete this post"
            comments = db.GqlQuery(
            "select * from Comment where ancestor is :1 order by created desc limit 10", postkey) # NOQA

            self.render("permalink.html", post=post, comments=comments,
                        error_msg=error_msg)

app = webapp2.WSGIApplication([('/', MainPage),
                                ('/blog/?', BlogFront),
                                ('/blog/([0-9]+)', PostPage),
                                ('/blog/newpost', NewPost),
                                ('/blog/([0-9]+)/editpost/', EditPost),
                                ('/blog/([0-9]+)/deletepost/([0-9]+)', DeletePost),
                                ('/blog/([0-9]+)/addcomment/([0-9]+)', CreateComment),
                                ('/blog/newcomment', Comment),
                                ('/blog/signup', Register),
                                ('/blog/login', Login),
                                ('/blog/logout', Logout),
                                ('/blog/([0-9]+)/like', LikeHandler),
                                ('/blog/([0-9]+)/unlike', UnlikeHandler),
                                ],
                                debug=True)

