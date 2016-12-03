from google.appengine.ext import db

from user import User
import jinjaHelper


# Post Model
class Post(db.Model):
    """
        Holds blog post information.
    """

    user_id = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

    def render(self):
        self.render_text = self.content.replace('\n', '<br>')
        return jinjaHelper.jinja_render_str("post.html", post=self)
