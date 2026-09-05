from flask import Blueprint

reverify_tool_blueprint = Blueprint(
    "reverify_tool",
    __name__,
    template_folder="../../templates/reverify_tool",
)

from . import views  # noqa: E402, F401
