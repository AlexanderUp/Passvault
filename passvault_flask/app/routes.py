# encoding:utf-8

from flask import render_template
from flask import flash
from flask import redirect
from app import app
from app.forms import MasterPasswordForm


@app.route('/password_list')
def password_list():
    passwords = [
    {'entry':{'account':'example@mail.ru', 'password':'ed23bdb0e07af92933f7'}},
    {'entry':{'account':'example@gmail.com', 'password':'e5147cf7a1cb0533f7af'}}
    ]
    return render_template('password_list.html', title='Password list', passwords=passwords)

@app.route('/', methods=['GET', 'POST'])
def open_database():
    form = MasterPasswordForm()
    if form.validate_on_submit():
        flash('Master password entered!')
    return render_template('open_database.html', form=form)

@app.route('/close_database')
def close_database():
    return 'To be implemented'
