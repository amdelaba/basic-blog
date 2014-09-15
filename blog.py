import os
import re
import webapp2
import jinja2
import string
import logging
import sys 
import random
import json
import hashlib
import hmac
import time
from string import letters
from google.appengine.ext import db
from google.appengine.api import memcache

#DEBUG = os.environ['SERVER_SOFTWARE'].startswith('Development')


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        return render_str(template, **params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))




## HW3: Basic Blog

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def user_key(group = 'default'):
    return db.Key.from_path('users', group)

class BlogPost(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    last_cached = time.time()
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        post_id = str(self.key().id())
        return render_str("post.html", p = self, post_id = post_id)




class User(db.Model):
    username = db.StringProperty(required = True)
    pwd_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)


# returns json
def blog_to_json(blog):
    blog_dict = {}
    
    # blog_id = blog.key().id()  #delete later
    # blog_dict['blog_id'] = blog_id
    
    blog_dict['subject'] = blog.subject
    blog_dict['content'] = blog.content
    blog_dict['created'] = blog.created.strftime("%b %d, %Y")
    blog_dict['last_modified'] = blog.last_modified.strftime("%b %d, %Y")
    return blog_dict


LAST_CACHED = time.time()

def top_blogs(update = False):
    global LAST_CACHED
    key = 'top'
    blogs = memcache.get(key)
    if blogs is None or update:
        logging.error('\nDB QUERY\n')
        blogs = db.GqlQuery("select * from BlogPost order by created desc limit 10")
        blogs = list(blogs)
        memcache.set(key, blogs)
        LAST_CACHED = time.time()
    return blogs



class BlogFrontHandler(Handler):
    def get(self):
        if self.request.url.endswith('.json'):
            self.response.headers['Content-Type'] = 'application/json'
            blogs = top_blogs()
            blog_list = []
            for blog in blogs:
                blog_list.append(blog_to_json(blog))
            self.write(json.dumps(blog_list))
        else:
            posts = top_blogs()
            cache_time = int(time.time() - LAST_CACHED)
            self.render('front.html', posts = posts, cache_time = cache_time)  
    



#LAST_CACHED_CURRENT = time.time()
def get_current_blog(blog_id, update = False):
    #global LAST_CACHED_CURRENT
    
    key = str(blog_id)
    blog = memcache.get(key)
    if blog is None or update:
        logging.error('\nDB QUERY: Permalink\n')
        post_key = db.Key.from_path('BlogPost', int(blog_id), parent=blog_key())
        blog = db.get(post_key)
        blog.last_cached = time.time()
        memcache.set(key, blog)
    return blog


class PermalinkHandler(Handler):
    def get(self, post_id):
        if self.request.url.endswith('.json'):
            self.response.headers['Content-Type'] = 'application/json'
            blog = get_current_blog(post_id)
            blog_json = blog_to_json(blog)
            self.write(json.dumps(blog_json))
        else:
            blog = get_current_blog(post_id)
            if not blog:
                self.error(404)
                return
            cache_time = int(time.time() - blog.last_cached)
            self.render("permalink.html", post = blog, cache_time = cache_time)
   


class NewPostHandler(Handler):
    def get(self):
        self.render("newpost.html")
    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            p = BlogPost(parent = blog_key(), subject = subject, content = content)
            p.put()
            time.sleep(1)
            top_blogs(True)
            post_id = str(p.key().id())

            #update the cache
            #blog = get_current_blog(post_id, True)

            self.redirect('/blog/%s' % post_id)
        else: 
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)




## HW4: Authentication

# Hash cookies
SECRET = 'imsosecret'
def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


# Hash passwords
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)
#h = make_pw_hash('spez', 'hunter2')
#print valid_pw('spez', 'hunter2', h)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def user_exists(username):
    user_query = db.GqlQuery("select * from User where username='%s'" % username)
    result = user_query.get()
    if result:
        print "Username Exists Already: %s" %result.username 
        return True
    return False


class Signup(Handler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            # Hash pasword 
            pwd_hash = make_pw_hash(username,password)

            # Create User object
            user = User(parent = user_key(), username = username, pwd_hash = pwd_hash, email=email)

            # Check if user with username already exists, if so error,  dont 
            if user_exists(username):
                params['error_username'] = "That user already exists"   
                self.render('signup-form.html', **params)
            else:   
                # Add user to user table (userid(auto),username,hashed password, email)
                user.put()

                # Get user_id for cookies
                user_id = user.key().id()

                # Set-Cookie. with user id
                new_cookie_val = make_secure_val(str(user_id))
                self.response.headers.add_header('Set-Cookie', 'user_id=%s;Path=/' % new_cookie_val)

                # Redirect. Dont send username as param. use cookie in welcome page
                self.redirect('/blog/welcome') 
            

class Login(Handler):
    def get(self):
        self.render("login.html")
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        params = dict()

        if not username or not password:
            params['error_login'] = "Please enter Username and Password " 
            self.render('login.html', **params)
            return

        params = dict()
        user_query = db.GqlQuery("select * from User where username='%s'" % username)
        result = user_query.get()
        if result:
            pwd_hash = result.pwd_hash
            user_id = result.key().id()
            if valid_pw(username, password, pwd_hash):
                new_cookie_val = make_secure_val(str(user_id))
                self.response.headers.add_header('Set-Cookie', 'user_id=%s;Path=/' % new_cookie_val)
                self.redirect('/blog/welcome') 
                return
        params['error_login'] = "Invalid login" 
        self.render('login.html', **params)  


class Logout(Handler):
    def get(self):
        new_cookie_val = ""
        self.response.headers.add_header('Set-Cookie', 'user_id=%s;Path=/' % new_cookie_val)
        self.redirect('/blog/signup')

         
class Welcome(Handler):
    def get(self):
        user_id = ""

        # Get user_id cookie
        user_id_cookie_str = self.request.cookies.get('user_id')
        
        # if theres user_id cookie, check_secure_val
        # if valid extract user_id 
        if user_id_cookie_str:
            print >>sys.stderr, "user_id_cookie_str %s\n\n" % user_id_cookie_str
            cookie_val = check_secure_val(user_id_cookie_str)
            if cookie_val:
                user_id = int(cookie_val)
            else:   
                self.redirect('/blog/signup')
                return
        else:
            self.redirect('/blog/signup')
            return

        # get username from User that matches user_id
        key = db.Key.from_path('User', int(user_id), parent=user_key())
        user = db.get(key)
        if not user:
            self.redirect('/blog/signup')
            return
        
        # render
        username = user.username
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog/signup')




class VisitCountHandler(Handler):  
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        visits += 1
        new_cookie_val = make_secure_val(str(visits))
        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
        if visits > 10:
            self.write('Over 10!!!!')
        else:   
            self.write('You have been here %s times!' % visits)   


class UserHandler(Handler): 
    def get(self):
        users = db.GqlQuery("select * from User order by created asc")
        self.render('users.html', users = users) 


class FlushCache(Handler): 
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')

       


app = webapp2.WSGIApplication([ ('/blog/?(?:\.json)?', BlogFrontHandler ), #does not send json part as paramenter to get()
                                ('/blog/([0-9]+)(?:\.json)?', PermalinkHandler),
                                ('/blog/newpost', NewPostHandler ),
                                ('/blog/signup', Signup),
                                ('/blog/welcome', Welcome),
                                ('/blog/login', Login),
                                ('/blog/logout', Logout),
                                ('/visit', VisitCountHandler),
                                # ('/users', UserHandler), # for debugging
                                ('/blog/flush', FlushCache),
                                ], debug=True)


