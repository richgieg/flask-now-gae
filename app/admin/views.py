from flask import render_template
from ..auth.decorators import fresh_admin_required
from . import admin


@admin.route('/')
@fresh_admin_required
def index():
    return render_template('admin/index.html')
