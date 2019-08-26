# encoding:utf-8

from flask_wtf import FlaskForm
from wtforms import PasswordField
from wtforms import SubmitField
from wtforms.validators import DataRequired


class MasterPasswordForm(FlaskForm):
    master_password = PasswordField('Master_password', validators=[DataRequired()])
    submit = SubmitField('Submit')
