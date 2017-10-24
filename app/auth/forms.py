from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import Required, Email, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Required(), Length(1, 64), Email()])
    password = PasswordField("Password", validators=[Required()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log in")


class RegistrationForm(FlaskForm):
    email = StringField("Email", validators=[Required(),Length(1,64),
                                            Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
'                                         Usernames must have only letters, '
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

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField("Old password",validators=[Required()])
    new_password = PasswordField("New password", validators=[
        Required(), EqualTo('new_password2', message="Passwords must match")])
    new_password2 = PasswordField('Confirm your new password', validators=[
        Required()])
    submit = SubmitField("Change password")


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64),
                                             Email()])
    submit = SubmitField('Reset Password')


class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64),
                                             Email()])
    password = PasswordField('New Password', validators=[
        Required(),EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Reset Password')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('Unknown email adress')


class EmailAdressChangeForm(FlaskForm):
    new_email = StringField('New Email', validators=[Required(), Length(1,64),
                                                     Email()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Update Email Address')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
