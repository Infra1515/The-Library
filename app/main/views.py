from flask import render_template, redirect, url_for, abort, flash, request, \
current_app
from flask_login import login_required, current_user
from . import main
from .forms import EditProfileForm, AdminEditProfileForm, UploadForm, PostForm
from .. import db
from .. import images
from ..models import Role, User, Permission, Post
from ..decorators import admin_required
from werkzeug.datastructures import CombinedMultiDict


@main.route('/', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        post=Post(body=form.body.data,
                  author=current_user._get_current_object())
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['THE_LIBRARY_POST_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('index.html', form=form, posts=posts,
                           pagination=pagination)


@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = user.posts.order_by(Post.timestamp.desc()).all()
    return render_template('user.html', user=user, posts=posts)


@login_required
@main.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        current_user.profile_picture_service = form.profile_picture.data
        db.session.add(current_user)
        db.session.commit()
        flash('Your profile has been updated')
        if form.profile_picture.data == '2':
            return redirect(url_for('.upload_profile_picture'))
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    form.profile_picture.data = current_user.profile_picture_service
    return render_template('edit_profile.html', form=form)

@login_required
@main.route('/edit-profile', methods=['GET','POST'])
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = AdminEditProfileForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        user.profile_picture_service = form.profile_picture.data
        user.profile_picture_url = form.profile_picture_url
        db.session.add(user)
        db.session.commit()
        flash('The profile has been updated')
        return redirect(url_for('.user', username = user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    form.profile.picture.data= user.profile_picture_service
    form.profile_picture_url = user.profile_picu
    return render_template('edit_profile.html', form=form, user=user)

@login_required
@main.route('/upload-file', methods=['GET','POST'])
def upload_profile_picture():
    form = UploadForm(CombinedMultiDict((request.files, request.form)))
    if request.method == 'POST':
        if form.validate_on_submit():
              filename = images.save(request.files['profile_pic'])
              url = images.url(filename)
              current_user.profile_picture_filename = filename
              current_user.profile_picture_url = url
              db.session.add(current_user)
              db.session.commit()
              flash('Profile picture sucessfully uploaded')
              return redirect(url_for('.user', username=current_user.username))
    return render_template('profile_picture_upload.html', form=form)


@main.route('/post/<int:id>')
def post(id):
    post = Post.query.get_or_404(id)
    return render_template('post.html', posts=[post])


@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        db.session.commit()
        flash('Your post has been updated')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)
