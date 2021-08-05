import os
import smtplib

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required





# Configure application
app = Flask(__name__)


# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project2.db")


@app.route("/", methods=["GET"])
@login_required
def index():
    return render_template("index.html")
    
@app.route("/mail", methods=["GET"])
@login_required
def mail():
    """User's Mailing List"""
    if request.method == "GET":
        receivers = db.execute("SELECT first_name AS First_name, last_name AS Last_name, email AS Email FROM mailing_list WHERE sender_id = :sender_id ORDER BY last_name, first_name", sender_id=session['user_id']) 
    return render_template("mail.html", receivers=receivers)


@app.route("/remove_log", methods=["POST"])
@login_required
def remove_log():
    """Edit existing log"""
    entry_id = request.form.get("log_id")
    db.execute("DELETE FROM entries WHERE entry_id=:entry_id", entry_id=entry_id)
    
    flash("Diary entry deleted successfully!")
    return redirect("/holidays")
    
    

@app.route("/edit_log", methods=["GET", "POST"])
@login_required
def edit_log():
    """Edit existing log"""
    entry_id = request.form.get("log_id")
    
    if request.method == "GET":
        entry_id = request.form.get("log_id")
        print(entry_id)
        entry_before = db.execute("SELECT title AS Title, date AS Date, location AS Location, trip_id AS Trip_id, log AS Log FROM entries WHERE entry_id=:entry_id", entry_id=entry_id)
        print(entry_before)
        holidays = db.execute("SELECT trip_name AS Name FROM holidays WHERE holiday_id=:holiday_id", holiday_id=entry_before[0].get('Trip_id'))
        return render_template("edit_log.html", entry_before=entry_before, holidays=holidays)
    
     # Ensure entry title was submitted
    if not request.form.get("title"):
        return apology("Missing entry title!", 400)

    # Ensure date was submitted
    elif not request.form.get("date"):
        return apology("Missing date!", 400)
        
    # Ensure location was submitted
    elif not request.form.get("location"):
        return apology("Missing location!", 400)

    else:
        #Delete previous
        db.execute("UPDATE entries SET title=:title, date=:date, location=:location, log=:log, image=:image WHERE entry_id=:entry_id", \
                    title=request.form.get("title"), date=request.form.get("date"), location=request.form.get("location"), log=request.form.get("log"), \
                    image=request.form.get("img"), entry_id=entry_id)
        db.execute("DELETE FROM entries WHERE entry_id=:entry_id", entry_id=entry_id)
        db.execute("INSERT INTO entries (title, date, location, log, trip_id, image) VALUES (:title, :date, :location, :log, :trip_id, :image)",
                             title=request.form.get("title"), date=request.form.get("date"), location=request.form.get("location"), log=request.form.get("log"), 
                             trip_id=request.form.get("holiday"), image=request.form.get("img"))
        
        # Redirect user to home page
        flash("Diary entry updated successfully!")
        return redirect("/holidays")

       

@app.route("/send", methods=["GET", "POST"])
@login_required
def send():
    """Send log to mailing list"""
    entry_id = request.form.get("log_id")
    
    sender_name = db.execute("SELECT first_name AS Name FROM users WHERE id = :user_id", user_id=session['user_id'])
    user_name = sender_name[0].get('Name')
    sender_email = "sharemyholiday.bot@gmail.com"
    password = "a1234567!"
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, password)
  
    SQL_entry = db.execute("SELECT title AS Title, log AS Log FROM entries WHERE entry_id = :entry_id", entry_id=entry_id)
    title = SQL_entry[0].get('Title')
    log = SQL_entry[0].get('Log')
    
    SQL_mailing = db.execute("SELECT first_name AS Name, email AS Email FROM mailing_list WHERE sender_id = :user_id", user_id=session['user_id'])
    
    for person in SQL_mailing:
        rec_email = person.get('Email')
        rec_name = person.get('Name')

        msg = 'Subject: ' + title + '\n\nDear ' + rec_name + ',\n\n' + log + '\n\nFrom ' + user_name
        server.sendmail(sender_email, rec_email, msg)
        
    flash("Diary entry emailed successfully!")
    return redirect("/holidays")   

@app.route("/holiday", methods=["GET", "POST"])
@login_required
def holiday():
    """Access Holiday Entries"""
    if request.method == "POST":
        trip_id = request.form.get("trip_id")
        trip_list = db.execute("SELECT holiday_id AS id, trip_name AS name, start_date AS start, end_date AS end FROM holidays \
                               WHERE user_id = :user_id AND holiday_id = :trip_id", user_id=session['user_id'], trip_id=trip_id)
                               
        entry_list = db.execute("SELECT entry_id AS id, title AS Title, date AS Date, location AS Location, log AS Log, image AS Image FROM entries \
                                 WHERE trip_id = :trip_id ORDER BY date", trip_id=trip_id)
  
        return render_template("holiday.html", trip_list=trip_list, entry_list=entry_list, trip_id=trip_id)


@app.route("/holidays", methods=["GET"])
@login_required
def holidays():
    """Get holiday"""

    if request.method == "GET":
        holidays = db.execute("SELECT trip_name AS Trip, start_date AS Start, \
                               end_date AS End FROM holidays WHERE user_id = :user_id ORDER BY start_date", user_id=session['user_id'])
                               

        #execute select statement to fetch data to be displayed in combo/dropdown
        trip_list = db.execute("SELECT holiday_id AS id, trip_name AS Trip FROM holidays WHERE user_id = :user_id", user_id=session['user_id']) 

        #render template and send the set of tuples to the HTML file for displaying
        return render_template("holidays.html", holidays=holidays, trip_list=trip_list)
        
   
@app.route("/add_log", methods=["GET", "POST"])
@login_required
def add_log():
    """Add log to chosen holiday"""
    
    #trip = request.form.get("random")
    #print("Trip id: ")
    
    #print(trip)
    #SQL_trip = db.execute("SELECT trip_name AS Name FROM holidays WHERE holiday_id=1")
    #print(SQL_trip) */
    
    holiday_list = db.execute("SELECT trip_name AS Name, holiday_id AS id FROM holidays WHERE user_id=:user_id", user_id=session['user_id'])
    if request.method == "GET":
 
        return render_template("add_log.html", holiday_list=holiday_list)
        
    # Ensure entry title was submitted
    if not request.form.get("title"):
        return apology("Missing entry title!", 400)

    # Ensure date was submitted
    elif not request.form.get("date"):
        return apology("Missing date!", 400)
        
    # Ensure location was submitted
    elif not request.form.get("location"):
        return apology("Missing location!", 400)

    else:
        # Ensure user hasn't already used entry title for this holiday
        if len(db.execute("SELECT * FROM entries WHERE title = :title AND trip_id = :trip_id", title=request.form.get("title"), trip_id=request.form.get("holiday"))) == 0:
            
            # insert holiday to the database
            db.execute("INSERT INTO entries (title, date, location, log, trip_id, image) VALUES (:title, :date, :location, :log, :trip_id, :image)",
                             title=request.form.get("title"), date=request.form.get("date"), location=request.form.get("location"), log=request.form.get("log"), 
                             trip_id=request.form.get("holiday"), image=request.form.get("img"))
            
            # Redirect user to home page
            flash("Diary entry added successfully!")
            return redirect("/holidays")
        else:
            return apology("Please choose another title!", 400)
    
    

    
@app.route("/addholiday", methods=["GET", "POST"])
@login_required
def addholiday():
    """User adds new trip"""
    if request.method == "GET":
        return render_template("add_holiday.html")
        
        
    trip_name = request.form.get("trip_name")
    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")

    # Ensure trip name was submitted
    if not request.form.get("trip_name"):
        return apology("Missing trip name!", 400)

    # Ensure start date was submitted
    elif not request.form.get("start_date"):
        return apology("Missing start date!", 400)
        
    # Ensure start date was submitted
    elif not request.form.get("end_date"):
        return apology("Missing end date!", 400)

    # Ensure start date comes before end date
    elif start_date > end_date:
        return apology("Start date must be before end date", 400)
    else:
        # Ensure user hasn't already used trip name
        if len(db.execute("SELECT * FROM holidays WHERE trip_name = :trip_name AND user_id = :user_id", trip_name=trip_name, user_id=session['user_id'])) == 0:
            
            # insert holiday to the database
            uid = db.execute("INSERT INTO holidays (trip_name, start_date, end_date, user_id) VALUES(:trip_name, :start_date, :end_date, :user_id)",
                             trip_name=trip_name, start_date=start_date, end_date=end_date, user_id=session['user_id']) 
                             
            # Redirect user to home page
            flash("Holiday added successfully!")
            return redirect("/holidays")
        else:
            return apology("Please choose another trip name!", 400)
            
@app.route("/addmail", methods=["GET", "POST"])
@login_required
def addmail():
    """User adds new trip"""
    if request.method == "GET":
        return render_template("add_mail.html")


    # Ensure first name was submitted
    if not request.form.get("first_name"):
        return apology("Missing first name!", 400)

    # Ensure last name was submitted
    elif not request.form.get("last_name"):
        return apology("Missing last name!", 400)
        
    # Ensure email was submitted
    elif not request.form.get("email"):
        return apology("Missing email!", 400)

    else:
        # Ensure user hasn't already used trip name
        if len(db.execute("SELECT * FROM mailing_list WHERE email = :email AND sender_id = :sender_id", email=request.form.get("email"), sender_id=session['user_id'])) == 0:
            
            # insert holiday to the database
            uid = db.execute("INSERT INTO mailing_list (first_name, last_name, email, sender_id) VALUES(:first_name, :last_name, :email, :sender_id)",
                             first_name=request.form.get("first_name"), last_name=request.form.get("last_name"), email=request.form.get("email"), sender_id=session['user_id']) 
                             
            # Redirect user to home page
            flash("Receipient added successfully!")
            return redirect("/holidays")
        else:
            return apology("Email already on mailing list!", 400)

        
    
    

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    flash("Successfully logged out.")
    return redirect("/login")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Missing username!", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Missing password!", 400)

        # Ensure password equals condirmation password submitted
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords don't match!", 400)
        else:
            # Ensure username doesn't exist already in database
            if len(db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))) == 0:
                # hash the password
                pwdhash = generate_password_hash(request.form.get("password"))
                # insert user to the database
                uid = db.execute("INSERT INTO users (username, hash, first_name, email) VALUES(:username, :hash, :first_name, :email)",
                                 username=request.form.get("username"), hash=pwdhash, first_name=request.form.get("first_name"), 
                                 email=request.form.get("email"))
                session["user_id"] = uid
                # Redirect user to home page
                flash("Registered successfully!")
                return redirect("/")
            else:
                return apology("Please choose another username!", 400)

    return render_template("register.html")


@app.route("/change_pw", methods=["GET", "POST"])
@login_required
def change_pw():
    """Let user change the password"""
    if request.method == "GET":
        return render_template("change_pw.html")

    if request.method == "POST":
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("Missing password!", 400)

        # Ensure password equals condirmation password submitted
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords don't match!", 400)
        else:
            # hash the password
            pwdhash = generate_password_hash(request.form.get("password"))
            db.execute("UPDATE users SET hash = :hash WHERE id=:id", hash=pwdhash, id=session["user_id"])
            # Redirect user to home page
            flash("Password changed!")
            return redirect("/")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)