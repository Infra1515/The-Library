from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, make_response
from flask_login import login_required, current_user
from . import main
from .forms import EditProfileForm, AdminEditProfileForm, UploadForm, PostForm, \
    CommentForm, PMForm, SearchForm
from .. import db, models
from .. import images
from ..models import Role, User, Permission, Post, Comment, PersonalMessage
from ..decorators import admin_required, permission_required
from werkzeug.datastructures import CombinedMultiDict


@main.route('/', methods=['GET'])
def index():
    page = request.args.get('page', 1, type=int)
    show_followed = False
    show_liked = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
        show_liked = bool(request.cookies.get('show_liked', ''))
    if show_followed:
        query = current_user.followed_posts
    elif show_liked:
        query = current_user.liked_posts
    else:
        query = Post.query
    pagination = query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['THE_LIBRARY_POST_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('index.html', posts=posts,
                           show_followed=show_followed, show_liked=show_liked,
                           pagination=pagination)


@main.route('/new_post', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        post = Post(title=form.title.data,
                    body=form.body.data,
                    author=current_user._get_current_object(),
                    author_username= current_user._get_current_object().username)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('.index'))
    return render_template('new_post.html', form=form)



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
@main.route('/upload-file', methods=['GET', 'POST'])
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

@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,
                          post=post,
                          author=current_user._get_current_object())
        db.session.add(comment)
        db.session.commit()
        flash("Your comment has been published.")
        return redirect(url_for('.post', id=post.id, page=1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) // \
            current_app.config['THE_LIBRARY_COMMENTS_PER_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['THE_LIBRARY_COMMENTS_PER_PAGE'],
          error_out=False)
    comments = pagination.items
    return render_template('post.html', posts=[post], form=form,
                           comments=comments, pagination=pagination)


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


@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash("You are already following this user.")
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    flash("You are now following %s" % username)
    return redirect(url_for('.user', username=username))


@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash('You are not following this user')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are not following %s anymore.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['THE_LIBRARY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followers of",
                           endpoint='.followers', pagination=pagination,
                           follows=follows)


@main.route('/followed-by/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['THE_LIBRARY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followed by",
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)


@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    resp.set_cookie('show_liked', '', max_age=30*24*60*60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return resp


@main.route('/liked')
@login_required
def show_liked():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_liked', '1', max_age=30*24*60*60)
    return resp



@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['THE_LIBRARY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments,
                           pagination=pagination, page=page)


@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('.moderate',
                    page=request.args.get('page', 1, type=int)))


@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


@main.route('/like/<int:id>', methods=['GET', 'POST'])
@login_required
def like_post(id):
    post = Post.query.get_or_404(id)
    if current_user.is_liking_post(post):
        flash('You already like this post')
        return redirect(url_for('.post', id=post.id, page=1))
    current_user.like_post(post)
    flash("You now like %s" % post.title)
    return redirect(url_for('.post', id=post.id))


@main.route('/unlike/<int:id>', methods=['GET', 'POST'])
@login_required
def unlike_post(id):
    post = Post.query.get_or_404(id)
    if not current_user.is_liking_post(post):
        flash("You are not liking this post.")
        return redirect(url_for('.post', id=post.id, page=1))
    current_user.unlike_post(post)
    flash("You now unlike %s" % post.title)
    return redirect(url_for('.post', id=post.id))


@login_required
@main.route('/new_pm', methods=['GET', 'POST'])
def pm():
    form = PMForm()
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        receiver = User.query.filter_by(username=form.receiver.data).first()
        if receiver is None:
            flash("No such user. Check username!")
        else:
            pm = PersonalMessage(subject=form.subject.data,
                                 body=form.body.data,
                                 sender=current_user._get_current_object(),
                                 receiver=receiver)
            db.session.add(pm)
            db.session.commit()
            return redirect(url_for('.show_sent'))  # must return to inbox
    return render_template('new_pm.html', form=form)


@login_required
@main.route('/inbox', methods=['GET'])
def inbox():
    page = request.args.get('page', 1, type=int)
    show_received = False
    if current_user.is_authenticated:
        show_received = bool(request.cookies.get('show_received', ''))
    if show_received:
        query = current_user.received_messages
    else:
        query = current_user.sent_messages

    pagination = query.order_by(PersonalMessage.timestamp.desc()).paginate(
        page, per_page=current_app.config['THE_LIBRARY_POST_PER_PAGE'],
        error_out=False)

    messages = pagination.items
    return render_template('inbox.html', messages=messages,
                           show_sent=show_sent, show_received=show_received,
                           pagination=pagination)

@login_required
@main.route('/inbox/message/<int:id>', methods=['GET', 'POST'])
def message(id):
    message = PersonalMessage.query.get_or_404(id)
    return render_template('message.html', messages=[message])


@main.route('/inbox/received')
@login_required
def show_received():
    resp = make_response(redirect(url_for('.inbox')))
    resp.set_cookie('show_received', '1', max_age=30*24*60*60)
    return resp


@main.route('/inbox/sent')
@login_required
def show_sent():
    resp = make_response(redirect(url_for('.inbox')))
    resp.set_cookie('show_received', '', max_age=30*24*60*60)
    return resp


@main.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    if form.validate_on_submit:
        if form.by_post_title.data == '' and form.by_username.data != '':
            query = Post.query.filter(Post.author_username.ilike("%" + str(form.by_username.data) + "%"))
        elif form.by_username.data == '' and form.by_post_title.data != '':
            query = Post.query.filter(Post.title.ilike("%" + str(form.by_post_title.data) + "%"))
            # query = Post.query.whoosh_search(form.by_post_title)
        elif form.by_username.data != '' and form.by_post_title.data != '':
            query = Post.query.filter(Post.title.ilike("%" + str(form.by_post_title.data) + "%"),
                                      Post.author_username.ilike("%" + str(form.by_username.data) + "%"))
        else:
            query = Post.query
        page = request.args.get('page', 1, type=int)
        pagination = query.order_by(Post.timestamp.desc()).paginate(
            page, per_page=current_app.config['THE_LIBRARY_POST_PER_PAGE'],
            error_out=False)
        posts = pagination.items
        return render_template('search.html',
                               pagination=pagination,
                               posts=posts,
                               form=form)
    return render_template('search.html', form=form)


# query = User.query.filter_by(username=form.by_username.data).posts
# user = User.query.filter_by(username=username).first_or_404
# posts = user.posts.order_by(Post.timestamp.desc()).all()