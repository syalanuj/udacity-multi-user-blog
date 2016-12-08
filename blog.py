import re
import hmac

import webapp2

from google.appengine.ext import db

from user import User
from post import Post
from comment import Comment
from like import Like
import jinjaHelper

secret = 'topSecret'


def makeSecureVal(val):
    """
        Secure secret
    """
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def checkSecureVal(secure_val):
    """
        Verify secret
    """
    val = secure_val.split('|')[0]
    if secure_val == makeSecureVal(val):
        return val


class MultiUserBlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return jinjaHelper.jinja_render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def setSecureCookie(self, name, val):
        cookie_val = makeSecureVal(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def readSecureCookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and checkSecureVal(cookie_val)

    def login(self, user):
        self.setSecureCookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.readSecureCookie('user_id')
        self.user = uid and User.by_id(int(uid))


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class BlogFront(MultiUserBlogHandler):
    def get(self):
        deleted_post_id = self.request.get('deleted_post_id')
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts, deleted_post_id=deleted_post_id)


class PostPage(MultiUserBlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        if not post:
            self.error(404)
            return

        error = self.request.get('error')

        self.render("postDetails.html", post=post, noOfLikes = likes.count(), comments=comments, error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        c = ""
        if(self.user):
            likes = db.GqlQuery("select * from Like where post_id = " +
                                post_id + " and user_id = " + 
                                str(self.user.key().id()))

            if(self.request.get('like') and 
                self.request.get('like') == "update"):

                if(self.user.key().id() == post.user_id):
                    self.redirect("/blog/" + post_id +
                                    "?error=You cannot Like your" +
                                    "post.!!")
                    return
                elif likes.count() == 0:
                    l = Like(parent=blog_key(), user_id=self.user.key().id(),
                                post_id=int(post_id))
                    l.put()
            
            if(self.request.get('comment')):
                c = Comment(parent=blog_key(), user_id=self.user.key().id(),
                            post_id=int(post_id),
                            comment=self.request.get('comment'))
                c.put()
        else:
            self.redirect("/login?error= Login before " +
                          "edit or comment or like.!!")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")
        self.render("postDetails.html", post=post, noOfLikes = likes.count(), comments=comments, new=c)


class NewPost(MultiUserBlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), user_id=self.user.key().id(),
                     subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


class DeletePost(MultiUserBlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect("/?deleted_post_id="+post_id)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this record.")
        else:
            self.redirect("/login?error=You need to be logged, in order" +
                          " to delete your post!!")


class EditPost(MultiUserBlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to edit this record.")
        else:
            self.redirect("/login?error=You need to be logged, " +
                          "in order to edit your post!!")

    def post(self, post_id):
        
        if not self.user:
            self.redirect('/blog')
            return

        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                subject = self.request.get('subject')
                content = self.request.get('content')

                if subject and content:
                    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                    post = db.get(key)
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % post_id)
                else:
                    error = "subject and content, please!"
                    self.render("editpost.html", subject=subject,
                        content=content, error=error)
            else:
                self.redirect("/login?error=You need to be logged, " +
                          "in order to edit your post!!")


class DeleteComment(MultiUserBlogHandler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                c.delete()
                self.redirect("/blog/"+post_id+"?deleted_comment_id=" +
                              comment_id)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this comment.")
        else:
            self.redirect("/login?error=You need to be logged, in order to " +
                          "delete your comment!!")


class EditComment(MultiUserBlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                self.render("editcomment.html", comment=c.comment)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=You don't have access to edit this " +
                              "comment.")
        else:
            self.redirect("/login?error=You need to be logged, in order to" +
                          " edit your post!!")

    def post(self, post_id, comment_id):
        
        if not self.user:
            self.redirect('/blog')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment',
                                   int(comment_id), parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():    
                c.comment = comment
                c.put()
                self.redirect('/blog/%s' % post_id)
            else:
                self.redirect("/blog" + post_id + 
                                "?error=You don't have access to edit this" +
                                " comment.")
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(MultiUserBlogHandler):
    def get(self):
        self.render("signupForm.html")

    def post(self):
        
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "Not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Not a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Not a valid email."
            have_error = True

        if have_error:
            self.render('signupForm.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        
        u = User.by_name(self.username)
        if u:
            msg = 'User already exists.'
            self.render('signupForm.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(MultiUserBlogHandler):
    def get(self):
        self.render('loginForm.html', error=self.request.get('error'))

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('loginForm.html', error=msg)


class Logout(MultiUserBlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


app = webapp2.WSGIApplication([
                                ('/login', Login),
                               ('/logout', Logout),
                               ('/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ('/signup', Register),
                               ],
                              debug=True)
