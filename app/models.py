from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin
from . import db, login_manager


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    social_id = db.Column(db.String(64), unique = True)
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default = False)

    # methods for hashing the User password.
    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        """
        Calls generate_password_hash and the result is
        written to password_hash field in the user model.
        generate_password_hash(password, method=pbkdf2:sha1, salt_length=8) :
        This function takes a plain-text password and returns the password
        hash as a string that can be stored in the user database.
        """
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """
        check_password_hash(hash, password) : Takes a password hash re‐
        trieved from the database and the password entered by the user.
        A return value of True indicates that the password is correct
        """
        return check_password_hash(self.password_hash, password)

    # methods used for user account confirmation
    def generate_confirmation_token(self, expiration = 3600):
        """
        Function to generate confirmation tokens. Serializer class takes
        encryption key as argument and expiration time.
        The dumps() method generates a cryptographic signature for the data given
        as an argument and then serializes the data plus the signature token
        string.  The expires_in argument sets an expiration time for the token
         expressed in seconds.
        """
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm':self.id})

    def confirm(self,token):
        """  Function to confirm token and expiration time is valid.
        To decode the token, the serializer object provides a loads() method
        that takes the token as its only argument. The function verifies the
        signature(checks user id) and the expiration time and, if found valid,
        it returns the original data. When the loads() method is given an invalid
        token or a valid token that is expired, an exception is thrown.
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        # db.session.commit() must be added or the DB wont be register the change
        db.session.commit()
        return True

    # functions for reseting user password
    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password
        db.session.add(self)
        db.session.commit()
        return True

    #functions for changing the user email
    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self,token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        db.session.add(self)
        db.session.commit()
        return True

    def __repr__(self):
        return '<User %r>' % self.username

@login_manager.user_loader
def load_user(user_id):
    """ Callback function required by Flask-Login. Loads user given the
    identifier.
    The user loader callback function receives a user identifier as a Unicode
    string. The return value of the function must be the user object
    if available or None otherwise.
    """
    return User.query.get(int(user_id))
