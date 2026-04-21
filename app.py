from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, IntegerField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, NumberRange, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

# -------------------------
# Environment Variables
# -------------------------
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "fallback-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///firstapp.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit

# Secure session cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False   # make True on HTTPS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800

# Ensure upload folder exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# -------------------------
# Extensions
# -------------------------
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Security Headers
# force_https=False for local development
Talisman(app, content_security_policy=None, force_https=False)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# -------------------------
# Database Models
# -------------------------
class Student(db.Model):
    s_no = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    city = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"{self.s_no} - {self.first_name}"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# -------------------------
# Forms
# -------------------------
name_regex = r"^[A-Za-z\s\-]+$"
city_regex = r"^[A-Za-z\s\-]+$"
username_regex = r"^[A-Za-z0-9_]+$"


class StudentForm(FlaskForm):
    first_name = StringField(
        "First Name",
        validators=[
            DataRequired(),
            Length(min=2, max=100),
            Regexp(name_regex, message="Only letters, spaces and hyphens allowed.")
        ]
    )
    last_name = StringField(
        "Last Name",
        validators=[
            DataRequired(),
            Length(min=2, max=100),
            Regexp(name_regex, message="Only letters, spaces and hyphens allowed.")
        ]
    )
    age = IntegerField(
        "Age",
        validators=[
            DataRequired(),
            NumberRange(min=1, max=120)
        ]
    )
    city = StringField(
        "City",
        validators=[
            DataRequired(),
            Length(min=2, max=100),
            Regexp(city_regex, message="Only letters, spaces and hyphens allowed.")
        ]
    )
    submit = SubmitField("Save")


class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=4, max=100),
            Regexp(username_regex, message="Only letters, numbers and underscore allowed.")
        ]
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, max=128)
        ]
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class UploadForm(FlaskForm):
    file = FileField("Upload Image", validators=[DataRequired()])
    submit = SubmitField("Upload")


# -------------------------
# Helpers
# -------------------------
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


def sanitize_text(value: str) -> str:
    if not value:
        return ""
    return escape(value.strip())


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            abort(403)

        user = User.query.get(user_id)
        if not user or not user.is_admin:
            abort(403)

        return f(*args, **kwargs)
    return decorated_function


# -------------------------
# Routes
# -------------------------
@app.route("/")
def root():
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def home():
    form = StudentForm()

    if form.validate_on_submit():
        record = Student(
            first_name=sanitize_text(form.first_name.data),
            last_name=sanitize_text(form.last_name.data),
            age=form.age.data,
            city=sanitize_text(form.city.data)
        )
        db.session.add(record)
        db.session.commit()
        flash("Student added successfully.", "success")
        return redirect(url_for("home"))

    all_data = Student.query.order_by(Student.s_no.desc()).all()
    return render_template("index.html", all_data=all_data, form=form)


@app.route("/delete/<int:s_no>", methods=["POST"])
@login_required
def delete(s_no):
    record = Student.query.get_or_404(s_no)
    db.session.delete(record)
    db.session.commit()
    flash("Record deleted successfully.", "success")
    return redirect(url_for("home"))


@app.route("/update/<int:s_no>", methods=["GET", "POST"])
@login_required
def update(s_no):
    record = Student.query.get_or_404(s_no)
    form = StudentForm(obj=record)

    if form.validate_on_submit():
        record.first_name = sanitize_text(form.first_name.data)
        record.last_name = sanitize_text(form.last_name.data)
        record.age = form.age.data
        record.city = sanitize_text(form.city.data)
        db.session.commit()
        flash("Record updated successfully.", "success")
        return redirect(url_for("home"))

    return render_template("update.html", form=form, record=record)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))

        user = User(
            username=sanitize_text(form.username.data),
            is_admin=False
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if not user or not user.check_password(form.password.data):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user.id
        session["username"] = user.username
        session["is_admin"] = user.is_admin

        flash("Login successful.", "success")
        return redirect(url_for("home"))

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


# -------------------------
# Secure File Upload
# -------------------------
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    form = UploadForm()

    if form.validate_on_submit():
        file = request.files.get("file")

        if not file or file.filename == "":
            flash("No file selected.", "danger")
            return redirect(url_for("upload_file"))

        if not allowed_file(file.filename):
            flash("Invalid file type. Only png, jpg, jpeg, gif allowed.", "danger")
            return redirect(url_for("upload_file"))

        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)

        flash("File uploaded successfully.", "success")
        return redirect(url_for("upload_file"))

    return render_template("upload.html", form=form)


# -------------------------
# RBAC Admin Route
# -------------------------
@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    users = User.query.order_by(User.id.desc()).all()
    return render_template("admin.html", users=users)


@app.route("/admin/delete_user/<int:id>", methods=["POST"])
@login_required
@admin_required
def delete_user(id):
    user = User.query.get_or_404(id)

    # Optional safety: don't let admin delete themselves
    if user.id == session.get("user_id"):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin_panel"))

    db.session.delete(user)
    db.session.commit()
    flash("User deleted by admin.", "success")
    return redirect(url_for("admin_panel"))


# -------------------------
# Error Handlers
# -------------------------
@app.errorhandler(403)
def forbidden_error(error):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404


@app.errorhandler(429)
def ratelimit_error(error):
    return render_template("429.html"), 429


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template("500.html"), 500


# -------------------------
# DB Init
# -------------------------
with app.app_context():
    db.create_all()

    # Create one default admin if none exists
    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        admin_user = User(username="admin", is_admin=True)
        admin_user.set_password("Admin12345")
        db.session.add(admin_user)
        db.session.commit()


if __name__ == "__main__":
    app.run(debug=False)