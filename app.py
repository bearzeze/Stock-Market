import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd
import datetime as dt

IEX_API_KEY = "export API_KEY=pk_e7260e58ccd74cb092488737c7102848"

# Configure application
app = Flask(__name__, template_folder="template")

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
    user_ownerships = db.execute("""SELECT companies.symbol, companies.name, ownership.shares FROM ownership
                            JOIN companies ON company_id = companies.id
                            JOIN users ON users.id = user_id
                            WHERE user_id = ?;""", user_id)

    # Getting remainder of users cash
    data = db.execute("SELECT cash FROM users WHERE id = ?;", user_id)
    user_cash = data[0]["cash"]

    # Total in cash and stocks
    total = 0
    # Getting current stock price and total amount for every owned stock
    # Stock data list
    stock_data = []
    for ownership in user_ownerships:
        company_symbol = ownership["symbol"]
        current_stock_price = lookup(company_symbol)["price"]
        total_stock = current_stock_price * float(ownership["shares"])
        total += total_stock

        # This goes to the list of stock_data which is handled to the index.html
        current_company = {
            "symbol": company_symbol,
            "name": lookup(company_symbol)["name"],
            "shares": ownership["shares"],
            "price": current_stock_price,
            "total": total_stock
        }

        # If there is already some stock bought from same company just update its share - add it, just like current total price
        stock_data.append(current_company)

    # Total amount is at the end sum of total stocks and remainder user cash
    total += user_cash
    return render_template("index.html", cash=user_cash, total=total, stock_data=stock_data)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        stock_symbol = request.form.get("symbol")
        if not stock_symbol:
            return apology("Stock symbol cannot be blank")

        stock_data = lookup(stock_symbol)
        if not stock_data:
            return apology(f"Data for {stock_symbol} cannot be found")

        shares = request.form.get("shares")
        try:
            float(shares)
            ukucan_string = False
        except:
            ukucan_string = True

        if not shares or ukucan_string or float(shares) <= 0 or float(shares) != round(float(shares)):
            return apology("Shares must be positive integer")

        invoice = stock_data["price"] * float(shares)

        user_data = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])
        available_cash_amount = float(user_data[0]["cash"])

        if (available_cash_amount - invoice <= 0):
            return apology("You don't have enough money for transactions")

        # Update available cash for the user
        available_cash_amount -= invoice
        db.execute("UPDATE users SET cash = ? WHERE id = ?;", available_cash_amount, session["user_id"])

        # Time of the buying stocks
        time = dt.datetime.now()

        # Check whether company is already in the companies table, if not insert into table
        companies = db.execute("SELECT name FROM companies;")
        for company in companies:
            if company["name"] == stock_data["name"]:
                break
        else:
            db.execute("INSERT INTO companies (name, symbol) VALUES (?, ?);", stock_data["name"], stock_data["symbol"])

        company_id = db.execute("SELECT id FROM companies WHERE name = ? ;", stock_data["name"])[0]["id"]

        # Inserting into purchases table
        db.execute("INSERT INTO purchases (user_id, company_id, price, shares, date) VALUES (?, ?, ?, ?, ?);",
                   session["user_id"], company_id, stock_data["price"], int(shares), time)

        # Inserting into ownership table, unique combination of one user and one company can be, otherwise update shares
        data = db.execute("SELECT * FROM ownership WHERE user_id = ? AND company_id = ?;", session["user_id"], company_id)
        if len(data) == 0:
            db.execute("INSERT INTO ownership (user_id, company_id, shares) VALUES (?,?,?);",
                       session["user_id"], company_id, int(shares))
        else:
            new_shares = data[0]["shares"] + int(shares)
            db.execute("UPDATE ownership SET shares = ? WHERE user_id = ? AND company_id = ?;",
                       new_shares, session["user_id"], company_id)

        flash(f'{stock_symbol.upper()} successfully bought.')
        return redirect("/")

    elif request.method == "GET":
        return render_template("buy.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        stock_symbol = request.form.get("symbol")

        if not stock_symbol:
            return apology("Missing symbol")

        shares_to_sell = int(request.form.get("shares"))
        if not shares_to_sell or shares_to_sell <= 0:
            return apology("Missing shares")

        data = db.execute("""SELECT shares, company_id FROM ownership
                            JOIN companies ON company_id = companies.id
                            WHERE user_id = ? AND symbol = ?;""", session["user_id"], stock_symbol)

        shares_existing = data[0]["shares"]
        company_id = data[0]["company_id"]

        if shares_to_sell > shares_existing:
            return apology("You don't have so much shares to sell!")

        # Insert into purchases table
        price = lookup(stock_symbol)["price"]
        time = dt.datetime.now()
        db.execute("INSERT INTO purchases (user_id, company_id, price, shares, date) VALUES (?, ?, ?, ?, ?);",
                   session["user_id"], company_id, price, -shares_to_sell, time)

        # Update ownership with reduced number of shares
        new_shares = shares_existing - shares_to_sell
        db.execute("UPDATE ownership SET shares = ? WHERE user_id = ? AND company_id = ?;",
                   new_shares, session["user_id"], company_id)

        # If now new shares is zero, we will delete such record in ownership table
        if new_shares == 0:
            db.execute("DELETE FROM ownership WHERE shares = 0;")

        # Update new user cash state
        money_to_get = float(price) * float(shares_to_sell)
        user_data = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])
        old_cash = user_data[0]["cash"]
        new_cash = old_cash + money_to_get

        db.execute("UPDATE users SET cash = ? WHERE id = ?;", new_cash, session["user_id"])

        flash(f'{stock_symbol.upper()} successfully sold.')
        return redirect("/")

    elif request.method == "GET":
        data = db.execute("""SELECT companies.name, companies.symbol, ownership.shares FROM companies
                    JOIN ownership ON companies.id = company_id WHERE ownership.user_id = ?;""", session["user_id"])
        return render_template("sell.html", available_stocks=data)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # All purchase history for the logged user
    data = db.execute("""SELECT companies.symbol, price, shares, date FROM purchases
     JOIN companies ON company_id = companies.id
     WHERE user_id = ?;""", session["user_id"])

    return render_template("history.html", data=data)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    elif request.method == "GET":
        # If user is already login it will redirect to / route, if he tries /login route
        try:
            session["user_id"]
        except:
            return render_template("login.html")

        return redirect("/")




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
    if request.method == "POST":
        stock_symbol = request.form.get("symbol")
        if not stock_symbol:
            return apology("Stock symbol cannot be blank")

        stock_data = lookup(stock_symbol)
        if not stock_data:
            return apology(f"Data for {stock_symbol} cannot be found")

        return render_template("quoted.html", data=stock_data)

    elif request.method == "GET":
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        password_again = request.form.get("confirmation")

        data = db.execute("SELECT username FROM users;")
        
        # Some checking about user name
        if not username:
            return apology("Username cannot be blank")
        elif data != []:
            for person in data:
                if username == person["username"]:
                    return apology(f"Username {username} is already taken")

        # Some checking about user password 
        if not password or not password_again:
            return apology("Password cannot be blank")
        elif password != password_again:
            return apology("Password is not confirmed")

        # Inserting new user
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))
        return redirect("/")

    elif request.method == "GET":
        return render_template("registration.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():

    if request.method == "POST":
        # Password of the current user from the database
        old_pw_db = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])[0]["hash"]

        old_pw_form = request.form.get("old_password")
        new_pw_form = request.form.get("new_password")
        new_pw_confirmation = request.form.get("confirmation")

        if not old_pw_form or not new_pw_form or not new_pw_confirmation:
            return apology("Password cannot be blank!")

        if not check_password_hash(old_pw_db, old_pw_form):
            return apology("You didn't type correct current password!")

        if new_pw_form != new_pw_confirmation:
            return apology("You didn't confirm new password with same password!")

        # Update new password in the database
        db.execute("UPDATE users SET hash = ? WHERE id = ?;", generate_password_hash(new_pw_form), session["user_id"])

        flash('You were successfully changed password.')
        return redirect("/")

    elif request.method == "GET":
        return render_template("change_password.html")


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    # Current balance
    data = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])
    balance = float(data[0]["cash"])

    if request.method == "POST":

        additional_cash = request.form.get("cash")
        try:
            additional_cash = float(additional_cash)
            string_is_typed = False
        except:
            string_is_typed = True

        if not additional_cash or string_is_typed or additional_cash <= 0:
            return apology("Cash needs to be positive floating number!")

        # Update balance in the database
        balance += additional_cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?;", balance, session["user_id"])

        flash(f'You were successfully add {usd(additional_cash)}.')
        return redirect("/")

    elif request.method == "GET":
        return render_template("add_cash.html", balance=balance)


@app.route("/withdraw_cash", methods=["GET", "POST"])
@login_required
def withdraw_cash():
    # Current balance
    data = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])
    balance = float(data[0]["cash"])

    if request.method == "POST":

        withdraw_cash = request.form.get("cash")
        try:
            withdraw_cash = float(withdraw_cash)
            string_is_typed = False
        except:
            string_is_typed = True

        if not withdraw_cash or string_is_typed or withdraw_cash <= 0:
            return apology("Cash needs to be positive floating number!")

        if withdraw_cash > balance:
            return apology("Cannot withdraw more money that you have in balance!")

        # Update balance in the database
        balance -= withdraw_cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?;", balance, session["user_id"])

        flash(f'You were successfully withdraw {usd(withdraw_cash)}.')
        return redirect("/")

    elif request.method == "GET":
        return render_template("withdraw_cash.html", balance=balance)