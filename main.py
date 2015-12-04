import os
from app import create_app
from app.models import Role

# Seed role entities
Role.insert_roles()

# Create the app
app = create_app(os.getenv('FLASK_CONFIG') or 'default')
