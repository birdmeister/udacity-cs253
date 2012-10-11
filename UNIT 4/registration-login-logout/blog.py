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


#password hash using salt
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in range(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)



#cookie hashing and hash-validation functions
secret = 'manmanmanfu!up'

def make_secure_cookie(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_cookie(val):
        return val


       
        
#blog handler
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
    
    def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

    def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
   
   


class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')



class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)





class Signup(BlogHandler):
    def render_signup(self, name_error="", password_error="", verify_error="",email_error="",username="",email=""):
	    self.render("signup-form.html", error_username=name_error, error_password=password_error, error_verify=verify_error,
			error_email=email_error,username=username,email=email)
    
    def get(self):
	    self.render_signup()

    def post(self):
        have_error = False
        user_name     = self.request.get('username')
        user_password = self.request.get('password')
        user_verify   = self.request.get('verify')
        user_email    = self.request.get('email')

        
        name_error = password_error = verify_error = email_error = ""

        if not valid_username(user_name):
            name_error = "That's not a valid username"
	    have_error = True

        if not valid_password(user_password):
            password_error = "That's not a valid password"
            have_error = True 

        elif user_password != user_verify:
            verify_error = "Your passwords didn't match"
            have_error = True

        if not valid_email(user_email):
            email_error = "That's not a valid email"
            have_error = True
  
        if have_error:
		self.render_signup(name_error, password_error, verify_error, email_error, user_name, user_email)
        else:      
            
      	   
      	   u = User.gql("WHERE username = '%s'"%user_name).get()
        
           if u:
            	name_error = 'That user already exists.'
            	self.render_signup(name_error)
           else:
            # make salted password hash
            	h = make_pw_hash(user_name, user_password)
		u = User(username=user_name, password=h,email=user_email)
		
            	u.put()
                uid= str(make_secure_cookie(str(u.key().id()))) #dis is how we get the id from google data store(gapp engine)
		#The Set-Cookie header which is add_header method will set the cookie name user_id(value,hash(value)) to its value
		self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' %uid)
		self.redirect('/welcome')


class Login(BlogHandler):
    def render_login_page(self, username="", error=""):
		self.render('login-form.html', username=username, error=error)

    def get(self):
        self.render_login_page()

    def post(self):
        user_name = self.request.get('username')
        user_password = self.request.get('password')
        if valid_username(user_name) and valid_password(user_password):
		cookie_str = self.request.cookies.get('user_id')#getting cookie associated vit that name
		if cookie_str:	# if cookie exists
			cookie_val = check_secure_val(str(cookie_str)) #checking with its hash for verification
			u = User.get_by_id(int(cookie_val)) #we get the id associated vit cookie
			if u and valid_pw(user_name, user_password, u.password): #u.password is hashed password 
				self.redirect('/welcome')
        
        else:
            msg = 'Invalid login'
            self.ender_login_page(user_name, error = msg)


class Logout(BlogHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/signup')


class Welcome(BlogHandler):
     
  def get(self):
     cookie_val = self.request.cookies.get('user_id')#In this case we will get the value of key(in this case name) 
     
     if cookie_val: 
	user_id = check_secure_val(str(cookie_val))	
        u = User.get_by_id(int(user_id))
        self.render('welcome.html', username = u.username)
        #self.response.out.write("Welcome, "+u+"!")
     else:
        self.redirect('/signup')

			



app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout), 
                               ('/welcome', Welcome),
                               ],
                              debug=True)
