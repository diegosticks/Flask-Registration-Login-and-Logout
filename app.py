from flask import Flask, render_template, request, session, url_for, logging, redirect, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from passlib.hash import sha256_crypt

engine = create_engine("mysql+pymysql://root:sticks100@localhost/register")
# (mysql+pymysql://username:password@localhost/databasename)
db = scoped_session(sessionmaker(bind=engine))

app = Flask(__name__)


@app.route("/")
def home():
    return render_template('home.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('fname')
        last_name = request.form.get('lname')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        secure_password = sha256_crypt.encrypt(str(password))

        if password == confirm:
            db.execute(
                "INSERT INTO users(first_name, last_name, username, password) VALUES(:fname, :lname, :username, :password)",
                {"fname": first_name, "lname": last_name, "username": username, "password": secure_password})
            db.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Password mismatch', "danger")
            return render_template("register.html")

    return render_template('register.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        usernamedata = db.execute("SELECT username FROM users WHERE username=username", {'username': username}).fetchone()
        passworddata = db.execute("SELECT password FROM users WHERE username=username", {'username': username}).fetchone()
        
        if usernamedata is None:
            flash('Invalid username', 'danger')
            return render_template('login.html')
        else:
            for pas in passworddata:
                if sha256_crypt.verify(password, pas):
                    session['log'] = True
                    flash('Login successful', 'success')
                    return redirect('profile')
                else:
                    flash('Incorrect password', 'danger')
                    return render_template('login.html')

    return render_template('login.html')


@app.route("/profile")
def profile():
    return render_template("profile.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You've successfully logged out", "success")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.secret_key = '12345678diegosticks'
    app.run(debug=True)
