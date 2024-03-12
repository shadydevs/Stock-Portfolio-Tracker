import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

@app.context_processor
def inject_stage_and_region():
    if session.get("user_id") is None:
        return dict(x='x')
    user_id = session["user_id"]
    return dict(username=db.execute("SELECT username FROM users WHERE id=?;", user_id)[0]["username"])

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    
    symbols = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id=?;", user_id)
    shares = {}
    info = {}
    
    for sym in symbols:
        sh = db.execute("SELECT SUM(shares) AS total FROM transactions WHERE symbol=? AND user_id=?;", sym["symbol"], user_id)[0]["total"]
        if sh > 0:
            shares[sym["symbol"]] = sh
            info[sym["symbol"]] = lookup(sym["symbol"])
     
    cash = db.execute("SELECT * FROM users WHERE id=?;", user_id)[0]["cash"]
    
    total = 0
    for sym in info:
        total += info[sym]["price"] * shares[sym]
        
    total += cash
    return render_template("index.html", shares=shares, info=info, cash=cash, total=total)
    

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        sym = request.form.get("sym", "")
        shares = request.form.get("shares")
        
        if shares == '' or int(shares) < 1:
            return apology("Invalid shares", 400)
        
        info = lookup(sym)
        if not info:
            return apology("Invalid symbol", 400)
        
        user_id = session["user_id"]
        cash = db.execute("SELECT * FROM users WHERE id=?;", user_id)[0]["cash"]
        
        if info["price"] * int(shares) > cash:
            return apology("Can't afford")
        
        db.execute("INSERT INTO transactions (user_id, symbol, price, shares) VALUES(?, ?, ?, ?);", user_id, sym.lower(), info["price"], shares)
        db.execute("UPDATE users SET cash=? WHERE id=?;", cash-(info["price"] * int(shares)), user_id)
        
        return redirect("/")
    


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    if request.method == "GET":
        user_id = session["user_id"]
        info = db.execute("SELECT symbol, price, shares, trans_time FROM transactions WHERE user_id=?;", user_id)
        print (info)
        return render_template("history.html", info=info)
    


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        sym = request.form.get("sym")
        info = lookup(sym)
        if not info:
            return apology("Invalid symbol", 400)
        return render_template("result.html", info=info)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":    
        return render_template("register.html")
    else:
        name = request.form.get("username")
        passw = request.form.get("password")
        cPassw = request.form.get("cpassword")
        
        if passw != cPassw or not passw or not cPassw:
            return apology("Passwords do not match", 403)
        if not name:
            return redirect("register")
        
        rows = db.execute("SELECT * FROM users WHERE username = ?", name)
        if len(rows) > 0:
            return apology("username taken", 403)
        
        hashPass = generate_password_hash(passw)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?);", name, hashPass)
        
        rows = db.execute("SELECT * FROM users WHERE username = ?", name)
        session["user_id"] = rows[0]["id"]
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    
    user_id = session["user_id"]
    symbols = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id=?;", user_id)
    
    if request.method == "GET":
        return render_template("sell.html", symbols=symbols)
    else:
        shares = int(request.form.get("shares", 0))
        if shares == '' or shares < 0:
            return apology("Invalid shares", 400)
        if shares == 0:
            return redirect("/sell")
        for i in range(len(symbols)):
            sym = request.form.get("symbol", "").lower()
            if sym == symbols[i]["symbol"].lower():
                info = lookup(sym)
                if not info:
                    return apology("Invalid symbol", 400)
                
                cash = db.execute("SELECT * FROM users WHERE id=?;", user_id)[0]["cash"]
                available = db.execute("SELECT SUM(shares) AS total FROM transactions WHERE symbol=? AND user_id=?;", sym, user_id)[0]["total"]
                if shares > available:
                    return apology("Not Enough Shares", 400)

                cash += info["price"] * shares
                
                db.execute("INSERT INTO transactions (user_id, symbol, price, shares) VALUES(?, ?, ?, ?);", user_id, sym.lower(), info["price"], -1 * shares)
                db.execute("UPDATE users SET cash=? WHERE id=?;", cash, user_id)

                return redirect("/history")
        return apology("Invalid Symbol", 400)
