from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    email = db.Column(db.String(100), index=True, unique = True)
    password = db.Column(db.String(140), nullable = False)
    admin = db.Column(db.Boolean, default = 0)

    def __repr__(self):
        return "<User %r>" % (self.email)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50), nullable = False)
    event_date = db.Column(db.DateTime, nullable = False)
    description = db.Column(db.String(1000), nullable = False)
    creator = db.Column(db.Integer, db.ForeignKey('user.id'))


