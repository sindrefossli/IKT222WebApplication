import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from datetime import datetime, timedelta
import pyotp
import qrcode
import io
import base64
from requests_oauthlib import OAuth2Session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv


load_dotenv()  # Load environment variables from .env file


# Set up the Flask app
app = Flask(__name__, instance_relative_config=True)

# Use environment variables for sensitive data
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
if not CLIENT_ID or not CLIENT_SECRET:
    raise ValueError("Client ID and Client Secret must be set in environment variables.")

# Set up OAuth transport security for development only
if os.getenv("FLASK_ENV") == "development":
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

REDIRECT_URI = os.getenv("REDIRECT_URI")
AUTHORIZATION_BASE_URL = os.getenv("AUTHORIZATION_BASE_URL")
TOKEN_URL = os.getenv("TOKEN_URL")
USER_INFO_URL = os.getenv("USER_INFO_URL")

if not REDIRECT_URI or not AUTHORIZATION_BASE_URL or not TOKEN_URL or not USER_INFO_URL:
    raise ValueError("OAuth URIs must be set in environment variables.")

# Configure database URI
db_path = os.path.join(app.instance_path, 'Database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Session management: set session timeout, secure cookies
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_SECURE"] = True  # Only send cookies over HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript from accessing cookies
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)



#db = SQLAlchemy(app)
#bcrypt = Bcrypt(app)

# Database model for Role
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    # Relationship to link roles to users
    users = db.relationship('User', backref='role', lazy=True)



# Database model for User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    address = db.Column(db.String(500), nullable=True)  # Changed from bio to address
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    totp_secret = db.Column(db.String(16))  # Add this line to store the TOTP secret





# Function to add predefined roles and users
def add_predefined_roles_and_users():
    # Create roles
    admin_role = Role(name="admin")
    customer_role = Role(name="customer")

    # Check if roles already exist
    if Role.query.count() == 0:
        db.session.add(admin_role)
        db.session.add(customer_role)
        db.session.commit()

    # Check if the user already exists
    if User.query.count() == 0:  # Only create users if the database is empty
        predefined_users = [
            {
                "role": admin_role,
                "username": "admin",
                "email": "admin@example.com",
                "password": "Admin1.",
                "address": "Jon Lilletuns vei 19"
            }
        ]

        for user_data in predefined_users:
            hashed_password = bcrypt.generate_password_hash(user_data["password"]).decode("utf-8")
            user = User(role=user_data["role"], username=user_data["username"], email=user_data["email"], password=hashed_password,
                        address=user_data["address"])  # Changed bio to address
            db.session.add(user)

        db.session.commit()  # Save changes to the database
        print("Predefined roles and users added successfully.")
    else:
        print("Roles or users already exist in the database.")





@app.route("/")
def home():
    # Check if user is logged in
    user_id = session.get("user_id")
    logged_in = user_id is not None and User.query.get(user_id) is not None  # Check if the user exists in the database

    user_role_id = None
    if logged_in:
        user = User.query.get(user_id)
        user_role_id = user.role_id  # Get the user's role_id



    return render_template("index.html", logged_in=logged_in, user_role_id=user_role_id)





@app.route("/register-with-google")
def register_with_google():
    # Start the OAuth process for registration
    google = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=["openid", "email", "profile"])
    authorization_url, state = google.authorization_url(AUTHORIZATION_BASE_URL, access_type="offline")
    session["oauth_state"] = state
    session["is_registering_with_google"] = True  # Set a flag for registration
    return redirect(authorization_url)



@app.route("/login-with-google")
def login_with_google():
    google = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=["openid", "email", "profile"])
    authorization_url, state = google.authorization_url(AUTHORIZATION_BASE_URL, access_type="offline")
    session["oauth_state"] = state
    return redirect(authorization_url)

@app.route("/google-signin")
def google_signin():
    try:
        if session.get("oauth_state") != request.args.get("state"):
            flash("OAuth state mismatch; please try logging in again.", "danger")
            return redirect(url_for("login"))

        google = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, state=session["oauth_state"])
        token = google.fetch_token(
            TOKEN_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url
        )

        response = google.get(USER_INFO_URL)
        user_info = response.json()
        email = user_info["email"]
        username = user_info["name"]

        # Check if the user exists in the database
        user = User.query.filter_by(email=email).first()

        # Check if this is a registration attempt
        if session.pop("is_registering_with_google", False):
            # Register the user if they don't exist
            if user is None:
                customer_role_id = 2  # Assuming role 2 is for regular customers
                totp_secret = pyotp.random_base32()
                user = User(username=username, email=email, password="", role_id=customer_role_id, totp_secret=totp_secret)
                db.session.add(user)
                db.session.commit()

                # Log in the newly created user by setting session user_id
                session["user_id"] = user.id
                #flash("Account created and logged in successfully with Google!", "success")
                #print("Account created and logged in with google successfully.")
                return redirect(url_for("home"))

            else:
                flash("Account already exists with this email. Please log in.", "danger")
                return redirect(url_for("login"))

        # For login, if user doesn't exist, prevent login
        if user is None:
            #flash("No account found with this Google account. Please register first.", "danger")
            #print("User does not exist, redirect to register")
            return redirect(url_for("register"))

        # Log in the user if they already exist
        session["user_id"] = user.id
        #flash("Logged in with Google successfully!", "success")
        #print("Login with google success")
        return redirect(url_for("home"))

    except Exception as e:
       # print("Failed Google login:", e)
        flash("Google login failed. Please try again.", "danger")
        #print("Google login failed")
        return redirect(url_for("login"))







@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        customer_role_id = 2  # Role ID for customers

        # Create a TOTP secret for the user
        totp_secret = pyotp.random_base32()
        user = User(username=username, email=email, password=hashed_password,
                    role_id=customer_role_id, totp_secret=totp_secret)

        try:
            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id  # Set session after registration
            flash("Registration successful! Set up your 2FA by scanning the QR code.", "success")
            print("Successfully registered. Set up 2FA by scanning the QR code.")
            return redirect(url_for("display_qr_code"))  # Redirect to QR code display

        except Exception as e:
            db.session.rollback()
            flash("Username or email already exists.", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")


#QR code display
@app.route("/display_qr_code")
def display_qr_code():
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if user:
        totp = pyotp.TOTP(user.totp_secret)
        otp_auth_url = totp.provisioning_uri(name=user.email, issuer_name="YourAppName")
        print("Provisioning URL:", otp_auth_url)

        qr = qrcode.make(otp_auth_url)
        img_io = io.BytesIO()
        qr.save(img_io, 'PNG')
        img_io.seek(0)
        img_data = img_io.getvalue()
        img_base64 = base64.b64encode(img_data).decode('utf-8')

        return render_template("display_qr_code.html", qr_code_base64=img_base64)



    flash("User not found. Please register first.", "danger")
    return redirect(url_for("register"))



@app.route("/verify_2fa", methods=["POST"])
def verify_2fa():
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if user:
        totp = pyotp.TOTP(user.totp_secret)
        totp_code = request.form.get("totp_code")  # Get TOTP code from the form

        if totp.verify(totp_code):  # Verify the TOTP code
            flash("2FA verification successful! You are now logged in.", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid 2FA code. Please try again.", "danger")
            return redirect(url_for("display_qr_code"))  # Stay on the QR code page if verification fails

    flash("User not found. Please log in first.", "danger")
    return redirect(url_for("login"))



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Initialize session variables for failed attempts and lockout
        if "failed_attempts" not in session:
            session["failed_attempts"] = 0
            session["lockout_until"] = None

        # Check if the user is locked out
        if session["lockout_until"]:
            lockout_until = datetime.strptime(session["lockout_until"], "%Y-%m-%d %H:%M:%S")
            if datetime.now() < lockout_until:
                # If the lockout period is still in effect
                remaining_time = (lockout_until - datetime.now()).seconds
                flash(f"Too many failed attempts. Please try again after {remaining_time} seconds.", "danger")
                return redirect(url_for("login"))
            else:
                # If the lockout period has passed, reset the failed attempts and lockout time
                session["failed_attempts"] = 0
                session["lockout_until"] = None

        user = User.query.filter_by(email=email).first()

        # Check if the user exists and password matches
        if user and bcrypt.check_password_hash(user.password, password):
            # If the user is an admin, skip TOTP verification
            if user.role.name == "admin":
                session["user_id"] = user.id  # Directly log in the admin
                flash("Logged in as Admin successfully!", "success")
                return redirect(url_for("home"))

            # Store user_id temporarily for TOTP verification for non-admin users
            session["temp_user_id"] = user.id  # Temporary session for TOTP verification
            return redirect(url_for("verify_totp_login"))  # Redirect to TOTP verification page
        else:
            # Increment the failed attempts
            session["failed_attempts"] += 1
            flash("Wrong credentials. Please check your email and password.", "danger")

            # After 3 failed attempts, apply a fixed lockout period of 30 seconds
            if session["failed_attempts"] >= 3:
                lockout_time = datetime.now() + timedelta(seconds=30)
                session["lockout_until"] = lockout_time.strftime("%Y-%m-%d %H:%M:%S")

                # Notify the user of the lockout time
                flash("Too many failed attempts. You are locked out for 30 seconds.", "danger")
                print("Too many failed attempts. Lockout for 30 seconds.")

    return render_template("login.html")











@app.route("/verify_totp_login", methods=["GET", "POST"])
def verify_totp_login():
    temp_user_id = session.get("temp_user_id")

    # Ensure the user has passed the first login phase
    if not temp_user_id:
        flash("Session expired or unauthorized access.", "danger")
        return redirect(url_for("login"))

    user = User.query.get(temp_user_id)

    if user.role.name == "admin":
        flash("Admin accounts do not need 2FA. You are logged in!", "success")
        session["user_id"] = user.id  # Directly log in the admin
        session.pop("temp_user_id", None)
        return redirect(url_for("home"))

    if request.method == "POST":
        totp_code = request.form["totp_code"]

        # Verify the TOTP code using the stored secret
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(totp_code):
            # Complete login by setting user_id in session and clearing temp_user_id
            session["user_id"] = temp_user_id
            session.pop("temp_user_id", None)
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid TOTP code. Please try again.", "danger")

    return render_template("verify_totp_login.html")




@app.route("/myAccount", methods=["GET", "POST"])
def myAccount():
    # Check if the user is logged in
    user_id = session.get("user_id")
    if user_id and User.query.get(user_id):  # Check if user exists in the database
        user = User.query.get(user_id)  # Get the current user from the database

        if request.method == "POST":
            # Handle the form submission for editing account details
            new_username = request.form.get("username")
            new_email = request.form.get("email")
            new_address = request.form.get("address", "")  # Changed from bio to address

            # Update user fields
            if new_username:
                user.username = new_username
            if new_email:
                user.email = new_email
            if new_address:
                user.address = new_address  # Changed bio to address

            # Commit changes to the database
            db.session.commit()
            flash("Account details updated successfully!", "success")
            return redirect(url_for("myAccount"))

        return render_template("myAccount.html", user=user)
    else:
        flash("You must be logged in to view this page.", "danger")
        return redirect(url_for("login"))


@app.route("/edit_address", methods=["POST"])
def edit_address():
    user_id = session.get("user_id")
    if user_id:
        user = User.query.get(user_id)
        if user:  # Ensure the user exists
            user.address = request.form.get("address", "")  # Changed from bio to address
            db.session.commit()  # Save changes to the database
            flash("Address updated successfully!", "success")
            return redirect(url_for("myAccount"))
    flash("You must be logged in to edit your address.", "danger")
    return redirect(url_for("login"))


@app.route("/inventoryManagement")
def inventoryManagement():
    user_id = session.get("user_id")
    if user_id and User.query.get(user_id):  # Check if user exists in the database
        user = User.query.get(user_id)  # Get the current user from the database
        return render_template("inventoryManagement.html", user=user)  # Create a corresponding HTML page
    else:
        flash("You must be logged in to view this page.", "danger")
        return redirect(url_for("login"))




@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)