from __future__ import absolute_import

import flask as f

from . import server


def create_app(extra_config=None):
    """
    Create a Flask app instance for the MWCP API.

    :param dict extra_config: Extra configuration options to add to the app
    :return: Flask app for MWCP API
    """
    app = f.Flask(__name__)

    app.config.setdefault("MENU_LINKS", []).extend(
        [
            {"name": "Upload", "endpoint": "mwcp.upload"},
            {"name": "Parsers", "endpoint": "mwcp.parsers_list"},
        ]
    )

    if extra_config:
        app.config.from_mapping(extra_config)

    server.init_app(app)
    app.register_blueprint(server.bp)

    return app
