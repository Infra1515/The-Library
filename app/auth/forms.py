from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import Required, Email, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Required(), Length(1,64), Email()])
    password = PasswordField("Password", validators=[Required()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log in")

class RegistrationForm(FlaskForm):
    email = StringField("Email", validators=[Required(),Length(1,64),
                                            Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
'                                     Usernames must have only letters, '
                                      'numbers, dots or underscores')])
    password = PasswordField("Password", validators=[
        Required(),EqualTo("password2", message = "Passwords must be the same !")])
    password2 = PasswordField("Confirm password", validators=[Required()])
    submit = SubmitField("Register")


    def validate_email(self, field):
        """ When a form defines a method with the prefix validate_ followed
            by the name of a field, the method is invoked in addition to any
            regularly defined validators. The custom validators for email
            and username ensure that the values given are not duplicates.
            The custom validators indicate a validation error by throwing a
            ValidationError exception with the text of the error message as
            argument.
        """
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')
