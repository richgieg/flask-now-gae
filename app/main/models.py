from google.appengine.ext import ndb


class Profile(ndb.Model):
    name = ndb.StringProperty(indexed=False)
    location = ndb.StringProperty(indexed=False)
    about_me = ndb.TextProperty()
