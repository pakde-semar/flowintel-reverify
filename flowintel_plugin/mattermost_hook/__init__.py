from flask import Blueprint

mattermost_hook_blueprint = Blueprint(
    'mattermost_hook_blueprint',
    __name__,
    template_folder='templates'
)

from . import views
