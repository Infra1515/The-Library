from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, \
    current_user
from . import auth
from .. import db
from ..models import User
from ..email import send_email
from . forms import LoginForm, RegistrationForm,ChangePasswordForm, \
    ResetPasswordRequestForm, ResetPasswordForm, EmailAdressChangeForm
from . oauth import OAuthSignIn

@auth.before_app_request
def before_request():
    """
    Function that runs before the user request.
    Checks if the user has confirmed his account.
    If not - redirects him to the route for unconfirmed users
    """
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint \
                and request.endpoint[:5] != 'auth.' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

@auth.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit(): # if it is POST request
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/authorize/<provider>')
def oauth_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()

@auth.route('/callback/<provider>')
def oauth_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    oauth = OAuthSignIn.get_provider(provider)
    if 'facebook' in provider:
        social_id, username, email = oauth.callback()
        if social_id is None:
            flash('Authentication failed.')
            return redirect(url_for('main.index'))
        user = User.query.filter_by(social_id = social_id).first()
        if not user:
            user = User(social_id = social_id, username=username, email = email)
            db.session.add(user)
            db.session.commit()

    if 'google' in provider:
        username, email = oauth.callback()
        if email is None:
            flash('Authentication failed.')
            return redirect(url_for('index'))
        user = User.query.filter_by(email=email).first()
        if not user:
            nickname = username
            if nickname is None or nickname == "":
                    nickname = email.split('@')[0]

            user = User(nickname=nickname,email=email)
            db.session.add(user)
            db.session.commit()
    login_user(user, True)
    return redirect(url_for('main.index'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email = form.email.data,
                 username = form.username.data,
                 password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                    'auth/email/confirm', user=user, token=token)
        flash("A confirmation email has been sent to you by email.")
        login_user(user)
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash("Your account has been confirmed. Congratulations!")
    else:
        flash("The confirmation link is invalid or has expired")
    return redirect(url_for('main.index'))

@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
                'auth/email/confirm', user=current_user, token=token    )
    flash("A new confirmation email has been sent to you by email")
    return redirect(url_for('main.index'))

@auth.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.new_password.data
            db.session.add(current_user)
            db.session.commit()
            flash("You have sucessfully changed your password")
            return redirect(url_for('main.index'))
        else:
            flash("Invalid password")
    return render_template("auth/change_password.html", form=form)

# must be added to login screen, no logic to reset it once you are logged in
@auth.route('/reset-password', methods=['GET','POST'])
@login_required
def reset_password_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                      'auth/email/reset_password', user=user, token=token,
                      next=request.args.get('next'))
        flash('An email with instructions to reset your password has been '
                'sent to you')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)

@auth.route('/reset-password/<token>', methods=['GET','POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)

@auth.route('/change-email', methods=['GET','POST'])
def email_change_request():
    form = EmailAdressChangeForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.new_email.data
            token = current_user.generate_email_change_token(new_email)
            send_email(current_user.email, "Confirm your email adress",
                       'auth/email/change_email', user=current_user, token=token)
            flash('A message has been sent to your new email adress. '
                    'Please open it and confirm the change.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password')
        return render_template('auth/chane_email.html', form=form)
    return render_template('auth/change_email.html', form=form)

@auth.route('/change-email/<token>', methods=['GET','POST'])
def change_email(token):
    if current_user.change_email(token):
        flash('Your email adress has been updated')
    else:
        flash('Invalid request')
    return redirect(url_for('main.index'))
