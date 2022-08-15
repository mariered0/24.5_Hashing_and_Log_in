from flask import Flask, render_template, redirect, session, flash, request
from flask_debugtoolbar import DebugToolbarExtension


from models import connect_db, db, User, Feedback
from forms import AddFeedbackForm, UserForm, LoginForm
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///feedback_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY', 'hellosecret1')
print('*********************************')
print('*********************************')
print('*********************************')
print(app.config['SECRET_KEY'])
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)

@app.route('/')
def home_page():
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """Show secret page if registered, otherwise show register form."""
    form = UserForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = User.register(username, password, email, first_name, last_name)

        db.session.add(new_user)
        db.session.commit()
        session['username'] = new_user.username

        flash('Welcome! Successfully Created Your Account!', 'success')
        return redirect(f'/users/{new_user.username}')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    """Show secret page if logged in, otherwise, shoe login form."""
    form = LoginForm()

    if "username" in session:
        return redirect(f"/users/{session['username']}")

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.authenticate(username, password)
        if user:
            flash('Welcome back!', 'success')

            session['username'] = user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = ['Invalid username/password']
            return redirect(f'/users/{user.username}')

    return render_template('login.html', form=form)
    

@app.route('/users/<username>')
def show_user(username):
    """Show secret page."""
    if "username" not in session or username != session['username']:
        return flash('Please login first.', 'danger')

    user = User.query.filter_by(username=session['username']).first()
    return render_template('user_details.html', user=user)

@app.route('/users/<username>', methods=['POST'])
def delete_user(username):
    """Delete user when the user is logged in."""
    if "username" not in session or username != session['username']:
        return flash('Please login first.', 'danger')

    user = User.query.filter_by(username=session['username']).first()
    db.session.delete(user)
    db.session.commit()

    session.pop('username')
    flash('User account deleted!', 'info')
    return redirect('/login')

@app.route('/logout')
def logout_user():
    """Log out users."""

    session.pop('username')
    flash('Goodbye!', 'success')
    return redirect('/')


@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    """Show a form to add feedback."""
    if "username" not in session or username != session['username']:
        return flash('Please login first.', 'danger')

    form = AddFeedbackForm()
    
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        new_feedback = Feedback(title=title, content=content, username=username)
        db.session.add(new_feedback)
        db.session.commit()

        flash('New feedback created!', 'success')
        return redirect(f'/users/{username}')

    return render_template('add_feedback.html', form=form)


@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    """Show a page where user can update their feedback."""
    form = AddFeedbackForm()
    feedback = Feedback.query.get(feedback_id)

    if "username" not in session or feedback.username != session['username']:
        return flash('Please login first.', 'danger')


    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()

        flash('Updated.', 'success')
        return redirect(f'/users/{feedback.username}')
    
    return render_template('update_feedback.html', form=form, feedback=feedback)


@app.route('/feedback/<id>/delete', methods=['POST'])
def delete_tag(id):
    """Delete feedback and show the user's feedback list."""

    feedback = Feedback.query.get_or_404(id)
    if "username" not in session or feedback.username != session['username']:
        flash("You don't have permission.", 'danger')
    
    db.session.delete(feedback)
    db.session.commit()

    return redirect(f'/users/{feedback.username}')


    
    