import os
from datetime import datetime, timezone, timedelta
from calendar import monthrange
from collections import defaultdict

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.fields import DateTimeLocalField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional, NumberRange

# APP CONFIGURATION
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "workload.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"


# DATABASE MODELS
class User(db.Model, UserMixin):
    """User model for authentication."""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationship to assignments
    assignments = db.relationship("Assignment", backref="user", lazy=True, cascade="all, delete-orphan")
    
    def set_password(self, password):
        """Hash and set the password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if password matches."""
        return check_password_hash(self.password_hash, password)


class Assignment(db.Model):
    """Assignment model for tracking work."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    
    # Assignment details
    title = db.Column(db.String(200), nullable=False)
    module = db.Column(db.String(50), nullable=True)
    estimated_hours = db.Column(db.Integer, default=1)
    due_at = db.Column(db.DateTime(timezone=True), nullable=False)
    
    # Status
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def is_urgent(self):
        """Check if due within 3 days."""
        if self.completed:
            return False
        now = datetime.now(timezone.utc)
        due = self.due_at
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        return due <= now + timedelta(days=3)
    
    def is_overdue(self):
        """Check if past due date."""
        if self.completed:
            return False
        now = datetime.now(timezone.utc)
        due = self.due_at
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        return now > due
    
    def days_until_due(self):
        """Get days until due date."""
        due = self.due_at
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        delta = due - datetime.now(timezone.utc)
        return delta.days


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return db.session.get(User, int(user_id))

# FORMS
class RegisterForm(FlaskForm):
    """User registration form."""
    name = StringField("Name", validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password", message="Passwords must match")])
    submit = SubmitField("Create Account")


class LoginForm(FlaskForm):
    """User login form."""
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")


class AssignmentForm(FlaskForm):
    """Form for adding/editing assignments."""
    title = StringField("Title", validators=[DataRequired(), Length(min=2, max=200)])
    module = StringField("Module Code", validators=[Optional(), Length(max=50)])
    estimated_hours = IntegerField("Estimated Hours", validators=[Optional(), NumberRange(min=1, max=100)])
    due_at = DateTimeLocalField("Due Date & Time", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    submit = SubmitField("Save")

# HELPER FUNCTIONS
def to_utc(dt_naive):
    """Convert naive datetime to UTC."""
    if dt_naive is None:
        return None
    return dt_naive.replace(tzinfo=timezone.utc)


# AUTH ROUTES
@app.route("/")
def home():
    """Home page - redirect based on auth status."""
    if current_user.is_authenticated:
        return redirect(url_for("assignments"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration page."""
    if current_user.is_authenticated:
        return redirect(url_for("assignments"))
    
    form = RegisterForm()
    
    if form.validate_on_submit():
        # Check if email already exists
        existing = User.query.filter_by(email=form.email.data.lower().strip()).first()
        if existing:
            flash("An account with this email already exists.", "danger")
            return render_template("register.html", form=form)
        
        # Create new user
        user = User(
            email=form.email.data.lower().strip(),
            name=form.name.data.strip()
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        # Log them in
        login_user(user)
        flash(f"Welcome, {user.name}! Your account has been created.", "success")
        return redirect(url_for("assignments"))
    
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login page."""
    if current_user.is_authenticated:
        return redirect(url_for("assignments"))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower().strip()).first()
        
        if user and user.check_password(form.password.data):
            login_user(user)
            flash(f"Welcome back, {user.name}!", "success")
            
            # Redirect to next page if specified
            next_page = request.args.get("next")
            return redirect(next_page if next_page else url_for("assignments"))
        
        flash("Invalid email or password.", "danger")
    
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    """Log out the current user."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# FEATURE 1: ASSIGNMENT MANAGEMENT
@app.route("/assignments")
@login_required
def assignments():
    """View all pending assignments (S2: View Sorted)."""
    pending = (
        Assignment.query
        .filter_by(user_id=current_user.id, completed=False)
        .order_by(Assignment.due_at.asc())
        .all()
    )
    return render_template("assignments.html", assignments=pending)


@app.route("/assignments/completed")
@login_required
def completed_assignments():
    """View completed assignments."""
    completed = (
        Assignment.query
        .filter_by(user_id=current_user.id, completed=True)
        .order_by(Assignment.completed_at.desc())
        .all()
    )
    return render_template("completed.html", assignments=completed)


@app.route("/assignments/add", methods=["GET", "POST"])
@login_required
def add_assignment():
    """Add a new assignment (S1: Add Assignment)."""
    form = AssignmentForm()
    
    if form.validate_on_submit():
        assignment = Assignment(
            user_id=current_user.id,
            title=form.title.data.strip(),
            module=form.module.data.strip().upper() if form.module.data else None,
            estimated_hours=form.estimated_hours.data or 1,
            due_at=to_utc(form.due_at.data)
        )
        
        db.session.add(assignment)
        db.session.commit()
        
        flash(f"Assignment '{assignment.title}' added!", "success")
        return redirect(url_for("assignments"))
    
    return render_template("add.html", form=form)


@app.route("/assignments/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_assignment(id):
    """Edit an assignment (S3: Edit Assignment)."""
    assignment = Assignment.query.get_or_404(id)
    
    # Security check
    if assignment.user_id != current_user.id:
        flash("You don't have permission to edit this assignment.", "danger")
        return redirect(url_for("assignments"))
    
    form = AssignmentForm()
    
    if form.validate_on_submit():
        assignment.title = form.title.data.strip()
        assignment.module = form.module.data.strip().upper() if form.module.data else None
        assignment.estimated_hours = form.estimated_hours.data or 1
        assignment.due_at = to_utc(form.due_at.data)
        
        db.session.commit()
        
        flash(f"Assignment '{assignment.title}' updated!", "success")
        return redirect(url_for("assignments"))
    
    # Pre-fill form
    if request.method == "GET":
        form.title.data = assignment.title
        form.module.data = assignment.module
        form.estimated_hours.data = assignment.estimated_hours
        form.due_at.data = assignment.due_at
    
    return render_template("edit.html", form=form, assignment=assignment)


@app.route("/assignments/delete/<int:id>", methods=["POST"])
@login_required
def delete_assignment(id):
    """Delete an assignment (S4: Delete)."""
    assignment = Assignment.query.get_or_404(id)
    
    if assignment.user_id != current_user.id:
        flash("You don't have permission to delete this assignment.", "danger")
        return redirect(url_for("assignments"))
    
    title = assignment.title
    db.session.delete(assignment)
    db.session.commit()
    
    flash(f"Assignment '{title}' deleted.", "info")
    return redirect(url_for("assignments"))


@app.route("/assignments/complete/<int:id>", methods=["POST"])
@login_required
def complete_assignment(id):
    """Mark assignment as complete (S4: Complete)."""
    assignment = Assignment.query.get_or_404(id)
    
    if assignment.user_id != current_user.id:
        flash("You don't have permission to modify this assignment.", "danger")
        return redirect(url_for("assignments"))
    
    assignment.completed = True
    assignment.completed_at = datetime.now(timezone.utc)
    db.session.commit()
    
    flash(f"'{assignment.title}' marked as complete!", "success")
    return redirect(url_for("assignments"))


@app.route("/assignments/uncomplete/<int:id>", methods=["POST"])
@login_required
def uncomplete_assignment(id):
    """Move assignment back to pending."""
    assignment = Assignment.query.get_or_404(id)
    
    if assignment.user_id != current_user.id:
        flash("You don't have permission to modify this assignment.", "danger")
        return redirect(url_for("completed_assignments"))
    
    assignment.completed = False
    assignment.completed_at = None
    db.session.commit()
    
    flash(f"'{assignment.title}' moved back to pending.", "info")
    return redirect(url_for("completed_assignments"))


# FEATURE 2: WORKLOAD CALENDAR
@app.route("/calendar")
@login_required
def calendar():
    """Monthly calendar view with clash detection (S5)."""
    # Get month/year from query params
    today = datetime.now(timezone.utc)
    year = request.args.get("year", today.year, type=int)
    month = request.args.get("month", today.month, type=int)
    
    # Handle overflow
    if month < 1:
        month, year = 12, year - 1
    elif month > 12:
        month, year = 1, year + 1
    
    # Get calendar info
    first_weekday, num_days = monthrange(year, month)
    
    # Date range for this month
    start_date = datetime(year, month, 1, tzinfo=timezone.utc)
    end_date = datetime(year + (1 if month == 12 else 0), (month % 12) + 1, 1, tzinfo=timezone.utc)
    
    # Get assignments for this month
    assignments = (
        Assignment.query
        .filter_by(user_id=current_user.id)
        .filter(Assignment.due_at >= start_date)
        .filter(Assignment.due_at < end_date)
        .all()
    )
    
    # Group by day
    by_day = defaultdict(list)
    for a in assignments:
        by_day[a.due_at.day].append(a)
    
    # Detect clashes (2+ pending assignments on same day)
    clashes = []
    for day, day_assignments in by_day.items():
        pending = [a for a in day_assignments if not a.completed]
        if len(pending) >= 2:
            clashes.append({
                "day": day,
                "count": len(pending),
                "titles": [a.title for a in pending],
                "hours": sum(a.estimated_hours or 0 for a in pending)
            })
    
    # Weekly workload warnings
    weekly_warnings = []
    for week in range(5):
        week_start = week * 7 + 1
        week_end = min(week_start + 6, num_days)
        
        week_hours = 0
        week_count = 0
        for day in range(week_start, week_end + 1):
            for a in by_day.get(day, []):
                if not a.completed:
                    week_hours += a.estimated_hours or 0
                    week_count += 1
        
        if week_hours >= 15:
            weekly_warnings.append({
                "week": week + 1,
                "start": week_start,
                "end": week_end,
                "hours": week_hours,
                "count": week_count,
                "level": "danger" if week_hours >= 25 else "warning"
            })
    
    # Build calendar grid
    calendar_weeks = []
    current_week = [None] * first_weekday
    
    for day in range(1, num_days + 1):
        day_assignments = by_day.get(day, [])
        pending = [a for a in day_assignments if not a.completed]
        
        current_week.append({
            "day": day,
            "assignments": day_assignments,
            "is_today": (year == today.year and month == today.month and day == today.day),
            "has_clash": len(pending) >= 2,
            "has_urgent": any(a.is_urgent() for a in day_assignments),
            "has_overdue": any(a.is_overdue() for a in day_assignments),
            "total_hours": sum(a.estimated_hours or 0 for a in pending)
        })
        
        if len(current_week) == 7:
            calendar_weeks.append(current_week)
            current_week = []
    
    # Pad last week
    if current_week:
        current_week.extend([None] * (7 - len(current_week)))
        calendar_weeks.append(current_week)
    
    # Month names
    months = ["", "January", "February", "March", "April", "May", "June",
              "July", "August", "September", "October", "November", "December"]
    
    return render_template("calendar.html",
        calendar_weeks=calendar_weeks,
        year=year,
        month=month,
        month_name=months[month],
        prev_year=year if month > 1 else year - 1,
        prev_month=month - 1 if month > 1 else 12,
        next_year=year if month < 12 else year + 1,
        next_month=month + 1 if month < 12 else 1,
        clashes=clashes,
        weekly_warnings=weekly_warnings
    )

# FEATURE 3: ANALYTICS DASHBOARD
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
    
    # On-time vs late completion
    on_time = sum(1 for a in completed if a.completed_at and a.completed_at <= a.due_at)
    
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
    
    # Sort by total
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
    
    # Busiest day of week
    day_counts = defaultdict(int)
    day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    for a in all_assignments:
        day_counts[a.due_at.weekday()] += 1
    
    busiest_days = [{"day": day_names[i], "count": day_counts[i]} for i in range(7)]
    
    stats = {
        "total": total,
        "completed": len(completed),
        "pending": len(pending),
        "overdue": len(overdue),
        "urgent": len(urgent),
        "completion_rate": completion_rate,
        "on_time": on_time,
        "late": len(completed) - on_time,
        "avg_hours": avg_hours,
        "pending_hours": pending_hours
    }
    
    return render_template("analytics.html",
        has_data=True,
        stats=stats,
        module_stats=module_stats,
        weekly_workload=weekly_workload,
        busiest_days=busiest_days
    )

# ERROR HANDLERS
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Something went wrong"), 500

# RUN APP
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("Database created!")
    
    print("Starting server at http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
