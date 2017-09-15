"""
For cases in which an entire view function needs to be made available
only to users with certain permissions, a custom decorator can be used.
Example usage:
@main.route('/admin')
@login_required
@admin_required
def for_admins_only():
    return "For administrators!"

@main.route('/moderator')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def for_moderators_only():
    return "For comment moderators!"
"""
from functools import wraps
from flask import abort
from flask_login import current_user
from .models import Permission


def permission_required(permission):
    """ Creates a custom decorator that checks permissions of user
    """
    def decorator(f):
        @wraps(f) # Takes a function used in a decorator and adds the
        #functionality of copying over the function name, docstring, args list..
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)
