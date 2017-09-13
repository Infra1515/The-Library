# Blueprint constructor for main.
from flask import Blueprint

main = Blueprint('main', __name__)

@main.app_context_processor
def inject_permissions():
    """
    Permissions need to be checked from templates. In that case the Permission
    class needs to be accessible to them globally. To avoid adding them as
    template argument at every render_template() call, a context processor
    is used. Context processors make variables globally available to all templates
    """
    return dict(Permission=Permission)

from . import views, errors
