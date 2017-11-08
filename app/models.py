from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app, request
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin, AnonymousUserMixin
from . import db, login_manager
from markdown import markdown
import bleach
import hashlib
import flask_whooshalchemy as wa


# fuser -n tcp -k 9001


class Permission:
    """ Bitflags denoting the permission of the user and therefore its role
    7 = normal user, 15 = moderator, 128 = administrator
    """
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class Role(db.Model):
    """ Class that defines the permission each user has.
    Users are assigned a discrete role, but the roles are defined in
    terms of permissions.
    The default field is set to True for only one role and False for all others.
    The role marked as default is the one assigned to new users upon registration.
    The permission field - integer that will be used as bitflag marking the
    permissions that a user has. Defined in the Permission class
    """
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')


    @staticmethod
    def insert_roles():
        """ class method for adding roles automatically to the DB.
        Does not create new role objects but tries to find existing ones
        and update them.
        """
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class Follow(db.Model):
    """ Self-referential many-to-many relationship table
    that implements follow-follower ability for the users"""
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class PostLikes(db.Model):

    __tablename__ = 'postlikes'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                        primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'),
                        primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class PersonalMessage(db.Model):

    __tablename__ = 'pm'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text);
    body_html = db.Column(db.Text)
    subject = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_read = db.Column(db.Boolean)

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p', '![]']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))


db.event.listen(PersonalMessage.body, 'set', PersonalMessage.on_changed_body)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    social_id = db.Column(db.String(64), unique = True)
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default = False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text)
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    profile_picture_filename = db.Column(db.String(64), default=None)
    profile_picture_url = db.Column(db.String(64), default=None)
    profile_picture_service = db.Column(db.String(64), default=None)
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    comments = db.relationship("Comment", backref='author', lazy='dynamic')

    sent_messages = db.relationship("PersonalMessage",
                                    foreign_keys=[PersonalMessage.sender_id],
                                    backref='sender',
                                    lazy='dynamic')

    received_messages = db.relationship("PersonalMessage",
                                        foreign_keys=[PersonalMessage.receiver_id],
                                        backref="receiver",
                                        lazy='dynamic')

    followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')

    post_likes = db.relationship('PostLikes',
                                 backref=db.backref('user', lazy='joined'),
                                 lazy='dynamic',
                                 cascade='all, delete-orphan')

    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    @staticmethod
    def add_self_follows():
        """Updates DB so that a user will follow himself"""
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def __init__(self, **kwargs):
        """ Constructor for the User model. Inherits from base class.
        If object has role, assigns one depending on email.
        if email == administrator = gives admin rights
        else gives default permissions(user)
        """
        super(User, self).__init__(**kwargs)
        # checks for user role
        if self.role is None:
            if self.email == current_app.config['THE_LIBRARY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        # generates avatar hash
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(
                self.email.encode('utf-8')).hexdigest()
        # assigns that a user follows himself - i.e see his own posts
        self.followed.append(Follow(followed=self))


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

    # functions for changing the user email
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
        self.avatar_hash = hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        db.session.commit()
        return True

    # functions for evaluating whether a user has a role
    def can(self, permissions):
        """
        Performs a bitwise 'and' operation between the requested
        permission and the permission assigned to the role.
        Returns True if all the requested bits are in the role and the
        user is allowed to perform the task
        """
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        """ Checks if the user is an admnistrator by comparing bitflags
        in role and needed bitflags for administrator rights
        """
        return self.can(Permission.ADMINISTER)

    # functions for updating when a user was last logged in
    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
    # functions for generating user avatar or profile picture

    def gravatar(self, size=100, default='mm', rating='g'):
        """ Takes as args size of avatar in pixels, type of icon
        and its rating - g,pg,r,x - indicates if an image is appropriate for
        certain audiences. Returns url to the generated avatar.
        The url is generated by concatenation of url, generated hash and
        function arguments
        """
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r{rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def allowed_file(self, filename):
        """
        Checks if the uploaded by the user file is allowed
        """
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)
            db.session.commit()

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)
            db.session.commit()

    def is_following(self, user):
        return self.followed.filter_by(
            followed_id=user.id).first() is not None

    def is_followed(self, user):
        return self.followers.filter_by(
            follower_id=user.id).first()

    @property
    def followed_posts(self):
        """Join operation to return posts only from those users
        that the current user is following. Query Posts and Follow.
        Returns those posts that match followed_id in Follow
        and user_id in Posts"""
        return Post.query.join(Follow, Follow.followed_id == Post.author_id)\
            .filter(Follow.follower_id == self.id)

    def like_post(self, post):
        if not self.is_liking_post(post):
            p = PostLikes(user=self, post=post)
            db.session.add(p)
            db.session.commit()

    def unlike_post(self, post):
        p = self.post_likes.filter_by(post_id=post.id).first()
        if p:
            db.session.delete(p)
            db.session.commit()

    def is_liking_post(self, post):
        return self.post_likes.filter_by(
            post_id=post.id).first() is not None

    @property
    def liked_posts(self):
        return Post.query.join(PostLikes, PostLikes.post_id == Post.id) \
            .filter(PostLikes.user_id == self.id)

    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):
    """ Defines can and is_administrator for anonymous users.
    This will enable the application to freely
    call current_user.can() and current_user.is_administrator() without
    having to check whether the user is logged in first.
    """

    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser

@login_manager.user_loader
def load_user(user_id):
    """ Callback function required by Flask-Login. Loads user given the
    identifier.
    The user loader callback function receives a user identifier as a Unicode
    string. The return value of the function must be the user object
    if available or None otherwise.
    """
    return User.query.get(int(user_id))


class Post(db.Model):
    __tablename__ = 'posts'
    __searchable__ = ['body', 'title']
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author_username = db.Column(db.Text)
    comments = db.relationship('Comment', backref='post', lazy='dynamic')
    user_likes = db.relationship('PostLikes', backref=db.backref('post', lazy='joined'),
                                 lazy='dynamic', cascade='all, delete-orphan')

    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1, 5)),
                     title=forgery_py.lorem_ipsum.title(4),
                     timestamp=forgery_py.date.date(True),
                     author=u,
                     author_username=u.username)
            db.session.add(p)
            db.session.commit()

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p', '![]']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))


db.event.listen(Post.body, 'set', Post.on_changed_body)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

