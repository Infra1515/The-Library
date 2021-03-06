from .. import images
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, SelectField,\
    SubmitField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms.validators import Required, Length, Email, Regexp, InputRequired
from wtforms import ValidationError
from flask_pagedown.fields import PageDownField
from ..models import Role, User


class NameForm(FlaskForm):
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('Submit')


class EditProfileForm(FlaskForm):
    name = StringField("Real name", validators=[Length(0,64)])
    location = StringField("Location", validators=[Length(0,64)])
    about_me = TextAreaField('About me')
    profile_picture = SelectField(u'Profile picture',
        choices = [('1','Facebook profile picture'),
                   ('2','Upload your own file'),
                   ('3','Use the Gravatar online service')])
    submit = SubmitField('Submit')


class AdminEditProfileForm(FlaskForm):
    email = StringField('Email', validators = [Required(), Length(1,64),
                                                Email()])
    username = StringField('Username', validators=[
        Required(), Length(1,64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,
                                    'Usernames must have only letters,'
                                    'numbers, dots or underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    name = StringField('Real name', validators=[Length(0,64)])
    location = StringField('Location', validators=[Length(0,64)])
    about_me = TextAreaField('About me')
    profile_picture = SelectField(u'Profile picture',
        choices = [('1','Facebook profile picture'),
                   ('2','Upload your own file'),
                   ('3','Use the Gravatar online service')])
    profile_picture_url = StringField("Profile picture URL",
        validators=[Length(0,256)])
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                            for role in Role.query.order_by(Role.name).all()]

        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class UploadForm(FlaskForm):
    profile_pic = FileField("Select your profile picture",
                            validators=[FileRequired(), FileAllowed(images, 'Images only!')])
    submit = SubmitField('Submit')


class PostForm(FlaskForm):
    title = StringField("Title", [InputRequired()])
    body = PageDownField("Express yourself!", validators=[Required()])
    tags = StringField("Post Tags")
    submit = SubmitField('Go')


class CommentForm(FlaskForm):
    body = StringField('', [InputRequired()])
    submit = SubmitField('Comment')


class PMForm(FlaskForm):
    receiver = StringField('Receiver', [InputRequired()])
    subject = StringField('Subject', [InputRequired()])
    body = PageDownField("Text", [InputRequired()])
    submit = SubmitField('Send')


class SearchForm(FlaskForm):
    by_username = StringField('Search by username')
    by_post_title = StringField('Search by post title')
    submit = SubmitField('Search')






