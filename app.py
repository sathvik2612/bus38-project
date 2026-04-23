import os
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy.query import Query
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.fields import DateTimeLocalField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from collections import defaultdict
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional, NumberRange


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    assignments = db.relationship("Assignment", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    module = db.Column(db.String(50), nullable=True)
    estimated_hours = db.Column(db.Integer, default=1)
    due_at = db.Column(db.DateTime(timezone=True), nullable=False)
    completed = db.Column(db.Boolean, nullable=False, default=False)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    def is_urgent(self):
        if self.completed:
            return False
        now = datetime.now(timezone.utc)
        due = self.due_at
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        return due <= now + timedelta(days=3)
    
    def is_overdue(self):
        if self.completed:
            return False
        now = datetime.now(timezone.utc)
        due = self.due_at
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        return now > due
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class RegisterForm(FlaskForm):
    name = StringField("Full name", validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    confirm = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")


class AssignmentForm(FlaskForm):
    title = StringField("Assignment title", validators=[DataRequired(), Length(min=2, max=200)])
    due_at = DateTimeLocalField("Due date & time", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    submit = SubmitField("Add assignment")

    def validate_due_at(self, due_at):
        if due_at and due_at.data < datetime.now():
            raise ValidationError("Due date cannot be set to the past")


def to_utc(dt_local_naive: datetime) -> datetime:
    local_ts = dt_local_naive.timestamp()
    return datetime.fromtimestamp(local_ts, tz=timezone.utc)


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    form = AssignmentForm()

    if form.validate_on_submit():
        assignment = Assignment(
            user_id=current_user.id,
            title=form.title.data.strip(),
            due_at=to_utc(form.due_at.data),
        )
        db.session.add(assignment)
        db.session.commit()
        flash("Assignment saved successfully!", "success")
        return redirect(url_for("dashboard"))

    assignments = (
        Assignment.query.filter_by(user_id=current_user.id)
        .order_by(Assignment.completed.asc(), Assignment.due_at.asc())
        .all()
    )

    return render_template("dashboard.html", form=form, assignments=assignments)


@app.route("/complete_assignment/<int:id>", methods=["GET", "POST"])
@login_required
def complete_assignment(id):
    assignment = Assignment.query.get_or_404(id)
    if current_user.id != assignment.user_id:
        flash("You are not authorised to access this assignment", "security")
        return redirect(url_for("dashboard"))
    assignment.completed = not assignment.completed
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/edit_assignments/<int:id>", methods=["GET", "POST"])
@login_required
def edit_assignments(id):
    assignment = Assignment.query.get_or_404(id)

    if current_user.id != assignment.user_id:
        return redirect(url_for("dashboard"))

    assignments = (
        Assignment.query.filter_by(user_id=current_user.id)
        .order_by(Assignment.completed.asc(), Assignment.due_at.asc())
        .all()
    )

    form = AssignmentForm(obj=assignment)

    if form.validate_on_submit():
        assignment.title = form.title.data
        assignment.due_at = form.due_at.data
        db.session.commit()
        return redirect(url_for("dashboard"))

    return render_template("edit_assignment.html", form=form, id=id, assignments=assignments)


@app.route("/delete_assignment/<int:id>", methods=["GET", "POST"])
@login_required
def delete_assignment(id):
    assignment = Assignment.query.get_or_404(id)
    if current_user.id != assignment.user_id:
        return redirect(url_for("dashboard"))
    db.session.delete(assignment)
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists. Please sign in.", "warning")
            return redirect(url_for("login"))

        user = User(email=email, name=form.name.data.strip())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash("Account created. You're signed in!", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(form.password.data):
            flash("Invalid email or password.", "danger")
            return render_template("login.html", form=form)

        login_user(user)
        flash("Signed in successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("login"))

@app.route("/analytics")
@login_required
def analytics():
    """Analytics dashboard with stats and charts (S6, S7)."""
    all_assignments = Assignment.query.filter_by(user_id=current_user.id).all()
    
    if not all_assignments:
        return render_template("analytics.html", has_data=False)
    
    # Basic counts
    total = len(all_assignments)
    completed = [a for a in all_assignments if a.completed]
    pending = [a for a in all_assignments if not a.completed]
    overdue = [a for a in pending if a.is_overdue()]
    urgent = [a for a in pending if a.is_urgent() and not a.is_overdue()]
    
    # Completion rate
    completion_rate = round((len(completed) / total) * 100) if total > 0 else 0
    
    # Hours
    total_hours = sum(a.estimated_hours or 0 for a in all_assignments)
    pending_hours = sum(a.estimated_hours or 0 for a in pending)
    avg_hours = round(total_hours / total, 1) if total > 0 else 0
    
    # Module breakdown
    module_stats = defaultdict(lambda: {"total": 0, "completed": 0, "hours": 0})
    for a in all_assignments:
        mod = a.module or "No Module"
        module_stats[mod]["total"] += 1
        module_stats[mod]["hours"] += a.estimated_hours or 0
        if a.completed:
            module_stats[mod]["completed"] += 1
    
    module_stats = dict(sorted(module_stats.items(), key=lambda x: x[1]["total"], reverse=True))
    
    # Weekly workload (next 4 weeks)
    today = datetime.now(timezone.utc)
    weekly_workload = []
    for week in range(4):
        week_start = today + timedelta(days=week * 7)
        week_end = week_start + timedelta(days=7)
        
        def in_week(a):
            due = a.due_at
            if due.tzinfo is None:
                due = due.replace(tzinfo=timezone.utc)
            return week_start <= due < week_end
        
        week_assignments = [a for a in pending if in_week(a)]
        week_hours = sum(a.estimated_hours or 0 for a in week_assignments)
        
        weekly_workload.append({
            "week": f"Week {week + 1}",
            "start": week_start.strftime("%d %b"),
            "count": len(week_assignments),
            "hours": week_hours,
            "level": "danger" if week_hours > 20 else ("warning" if week_hours > 10 else "success")
        })
    
    stats = {
        "total": total,
        "completed": len(completed),
        "pending": len(pending),
        "overdue": len(overdue),
        "urgent": len(urgent),
        "completion_rate": completion_rate,
        "avg_hours": avg_hours,
        "pending_hours": pending_hours
    }
    
    return render_template("analytics.html",
        has_data=True,
        stats=stats,
        module_stats=module_stats,
        weekly_workload=weekly_workload
    )
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
