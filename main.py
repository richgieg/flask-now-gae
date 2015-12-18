import os
from app import create_app
from app.auth.controllers import AuthController


# Seed role entities
AuthController.insert_roles()

# Create the app
app = create_app(os.getenv('FLASK_CONFIG') or 'default')
