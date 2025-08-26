import os
import re
import json
import logging
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError, OperationalError
import stripe
import time
from flask import Flask
from .config import Config


app = Flask(__name__)
app.config.from_object(Config)

# --- Config / Env -----------------------------------------------------------
try:
    from config import Config
except BaseException as e:
    raise RuntimeError("config.py missing or invalid. Please create it as per instructions.") from e

app = Flask(__name__)
app.config.from_object(Config)

# Static uploads folder
UPLOADS_DIR = os.path.join(app.static_folder, "Uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)
app.config.setdefault("UPLOAD_FOLDER", UPLOADS_DIR)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="app.log",
)
logger = logging.getLogger(__name__)

# Stripe Configuration
stripe.api_key = app.config.get('STRIPE_SECRET_KEY')
if not stripe.api_key or not stripe.api_key.startswith('sk_'):
    raise RuntimeError("Invalid or missing STRIPE_SECRET_KEY in config.py")
stripe.api_version = '2023-10-16'
webhook_secret = app.config.get('STRIPE_WEBHOOK_SECRET')

# Replace with actual Stripe Price IDs from the Stripe Dashboard
PRICE_ID_BASIC = '$9.99'  # Replace with actual Price ID for $9.99 AUD/month
PRICE_ID_ADVANCED = '$99.99'  # Replace with actual Price ID for $99.99 AUD/month
PRICE_ID_PREMIUM = '$999.99'  # Replace with actual Price ID for $999.99 AUD/month

# Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"
login_manager.login_message = "Please log in first to continue."

# --- JSON File Paths --------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DONATIONS_FILE = os.path.join(BASE_DIR, "donations.json")
INVESTMENTS_FILE = os.path.join(BASE_DIR, "investments.json")
SPONSORS_FILE = os.path.join(BASE_DIR, "sponsors.json")
TOTALS_FILE = os.path.join(BASE_DIR, "totals.json")

# --- Models -----------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    avatar_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    subscribed_email = db.Column(db.Boolean, default=False)  # Added for email subscription tracking

class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    idea = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # Stored in cents
    message = db.Column(db.Text, nullable=True)
    names = db.Column(db.Text, nullable=True)  # Field for delegated names
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user = db.relationship("User", backref=db.backref("donations", lazy=True))

class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    idea = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # Stored in cents
    benefits = db.Column(db.Text, nullable=True)
    names = db.Column(db.Text, nullable=True)  # Field for delegated names
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user = db.relationship("User", backref=db.backref("investments", lazy=True))

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    email = db.Column(db.String(255), nullable=False, default="")
    plan = db.Column(db.String(50), nullable=False, default="Free")
    status = db.Column(db.String(50), nullable=False, default="Active")
    stripe_subscription_id = db.Column(db.String(100), nullable=True)
    next_billing = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    user = db.relationship("User", backref=db.backref("subscriptions", lazy=True))

# --- Ensure email column exists in SQLite ---
with app.app_context():
    inspector = inspect(db.engine)
    if 'subscription' in inspector.get_table_names():
        columns = [c['name'] for c in inspector.get_columns('subscription')]
        if 'email' not in columns:
            db.session.execute(text('ALTER TABLE subscription ADD COLUMN email TEXT NOT NULL DEFAULT ""'))
            db.session.commit()
        if 'stripe_subscription_id' not in columns:
            db.session.execute(text('ALTER TABLE subscription ADD COLUMN stripe_subscription_id TEXT'))
            db.session.commit()
        if 'updated_at' not in columns:
            db.session.execute(text(f'ALTER TABLE subscription ADD COLUMN updated_at DATETIME DEFAULT "{datetime.now(timezone.utc).isoformat()}"'))
            db.session.commit()

# --- User Loader for Flask-Login --------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    try:
        user_id = int(user_id)
        user = db.session.get(User, user_id)
        if not user:
            logger.error(f"No user found for ID: {user_id}")
            session.clear()
            return None
        logger.info(f"Loaded user: {user.username}, ID: {user_id}, Email: {user.email}")
        return user
    except ValueError:
        logger.error(f"Invalid user_id format: {user_id}")
        session.clear()
        return None
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {str(e)}")
        db.session.rollback()
        return None

# --- JSON ↔ DB migration helpers -------------------------------------------
def load_json(file_path, default=None):
    if default is None:
        default = []
    try:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return default
    except Exception as e:
        logger.error(f"Error loading {file_path}: {e}")
        return default

def save_json(file_path, data):
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logger.info(f"Saved data to {file_path}")
    except Exception as e:
        logger.error(f"Error saving {file_path}: {e}")

def ensure_database_schema():
    try:
        with app.app_context():
            inspector = inspect(db.engine)
            if 'user' not in inspector.get_table_names():
                logger.info("Creating database tables...")
                db.create_all()
                return
            user_columns = [col['name'] for col in inspector.get_columns('user')]
            if 'password_hash' not in user_columns:
                logger.info("Adding missing password_hash column...")
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE user ADD COLUMN password_hash VARCHAR(255)"))
                default_hash = generate_password_hash("defaultpassword")
                users = User.query.all()
                for user in users:
                    if not user.password_hash:
                        user.password_hash = default_hash
                db.session.commit()
                logger.info(f"Set default password for {len(users)} existing user(s)")
            donation_columns = [col['name'] for col in inspector.get_columns('donation')]
            investment_columns = [col['name'] for col in inspector.get_columns('investment')]
            if 'names' not in donation_columns:
                logger.info("Adding names column to Donation table...")
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE donation ADD COLUMN names TEXT"))
            if 'names' not in investment_columns:
                logger.info("Adding names column to Investment table...")
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE investment ADD COLUMN names TEXT"))
            # Ensure subscribed_email column exists
            if 'subscribed_email' not in user_columns:
                logger.info("Adding subscribed_email column to User table...")
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE user ADD COLUMN subscribed_email BOOLEAN DEFAULT 0"))
                db.session.commit()
    except Exception as e:
        logger.error(f"Error ensuring database schema: {e}")
        logger.info("Recreating database tables...")
        db.drop_all()
        db.create_all()

def migrate_json_to_db():
    with app.app_context():
        try:
            ensure_database_schema()
            default_hash = generate_password_hash("defaultpassword")
            users_missing = User.query.filter(
                (User.password_hash.is_(None)) | (User.password_hash == "")
            ).all()
            changed = 0
            for u in users_missing:
                u.password_hash = default_hash
                changed += 1
            if changed:
                db.session.commit()
                logger.info(f"Set default password for {changed} user(s) without password_hash")

            donations_data = load_json(DONATIONS_FILE)
            for d in donations_data:
                username = d.get("username")
                if not username:
                    continue
                user = User.query.filter_by(username=username).first()
                if not user:
                    logger.warning(f"Skipping donation for non-existent user: {username}")
                    continue
                ts = datetime.fromisoformat(d["timestamp"]) if d.get("timestamp") else datetime.now(timezone.utc)
                exists = (
                    Donation.query.filter_by(user_id=user.id, idea=d.get("idea", "General"), amount=d["amount"], timestamp=ts).first()
                    is not None
                )
                if not exists:
                    db.session.add(
                        Donation(
                            user_id=user.id,
                            idea=d.get("idea", "General"),
                            amount=int(d["amount"] * 100),  # Convert to cents
                            message=d.get("message"),
                            names=d.get("names"),
                            timestamp=ts,
                        )
                    )

            investments_data = load_json(INVESTMENTS_FILE)
            for i in investments_data:
                username = i.get("username")
                if not username:
                    continue
                user = User.query.filter_by(username=username).first()
                if not user:
                    logger.warning(f"Skipping investment for non-existent user: {username}")
                    continue
                ts = datetime.fromisoformat(i["timestamp"]) if i.get("timestamp") else datetime.now(timezone.utc)
                exists = (
                    Investment.query.filter_by(user_id=user.id, idea=i.get("idea"), amount=i["amount"], timestamp=ts).first()
                    is not None
                )
                if not exists:
                    db.session.add(
                        Investment(
                            user_id=user.id,
                            idea=i.get("idea"),
                            amount=int(i["amount"] * 100),  # Convert to cents
                            benefits=i.get("benefits"),
                            names=i.get("names"),
                            timestamp=ts,
                        )
                    )

            # Initialize totals.json with NEIS funding for EcoKure
            totals_data = load_json(TOTALS_FILE, default={})
            if not totals_data:
                totals_data = {idea["name"]: 0.0 for idea in raw_ideas}
                totals_data["EcoKure"] = 23400.0  # NEIS funding in dollars
                save_json(TOTALS_FILE, totals_data)

            db.session.commit()
            logger.info("JSON data successfully migrated to database")
        except Exception as e:
            logger.error(f"Error in migrate_json_to_db: {e}")
            db.session.rollback()

# --- Ideas catalog ----------------------------------------------------------
raw_ideas = [
    {
        "name": "JARVI3",
        "description": "AI assistant aligned with the golden ratio.",
        "funding_goal": 150000,
        "funding_raised": 0,
        "banner": "images/ChatGPT Image Aug 9, 2025, 11_52_32 AM.png",
        "logo": "images/ChatGPT Image Aug 11, 2025, 09_11_41 AM.png",
        "pdf_url": "pdf/jarvi3(whitepaper).pdf",
        "whitepaper_preview": "Harmonious AI design leveraging phi principles for natural interaction.",
        "long_description": "An AI designed with golden ratio principles to enhance user experience.",
        "stage": "Development",
        "market": "AI Ethics",
        "benefits": "Free unlimited access with 1000 token bonus",
        "detail_endpoint": "jarvi3_details",
    },
    {
        "name": "QuantumSystemLock",
        "description": "AI-driven quantum encryption app.",
        "funding_goal": 100000,
        "funding_raised": 0,
        "banner": "images/qsl/5d5ead93-f52d-4072-96ba-328d0adbcfaf.png",
        "logo": "images/qsl/5d5ead93-f52d-4072-96ba-328d0adbcfaf.png",
        "pdf_url": "pdf/QuantumSystemLock(whitepaper11).pdf",
        "whitepaper_preview": "Secure data with quantum tech for unbreakable encryption.",
        "long_description": "A revolutionary app using quantum computing for top-tier security.",
        "stage": "Prototype",
        "market": "Cybersecurity",
        "benefits": "Lifetime free encryptions",
        "achievements": ["Patent filed"],
        "detail_endpoint": "quantum_system_lock_details",
    },
    {
        "name": "EcoKure",
        "description": "Sustainable living app with eco-friendly tips.",
        "funding_goal": 75000,
        "funding_raised": 0,
        "banner": "images/ecokure/Ecokurebackgroundwallpaper.png",
        "logo": "images/ecokure/ecokure_logo3.PNG",
        "pdf_url": "pdf/ecokurewhitepaper.pdf",
        "whitepaper_preview": "Promotes green living with actionable insights.",
        "long_description": "An app to guide users toward sustainable lifestyles.",
        "stage": "Planning",
        "market": "Green Tech",
        "benefits": "Free premium trial",
        "detail_endpoint": "ecokure_details",
    },
    {
        "name": "KureMechanics",
        "description": "Physics app exploring consciousness-based theories.",
        "funding_goal": 200000,
        "funding_raised": 0,
        "banner": "images/kure_mechanics/kuremechanicsbannor.png",
        "logo": "images/kure_mechanics/kuremechanicslogo.png",
        "pdf_url": "pdf/kuremechanicswhitrepaper.pdf",
        "whitepaper_preview": "Revolutionary physics tied to consciousness.",
        "long_description": "A platform for exploring new physics paradigms.",
        "stage": "Research",
        "market": "Education",
        "benefits": "Lifetime access",
        "detail_endpoint": "kure_mechanics_details",
    },
    {
        "name": "KureAcademy",
        "description": "Online learning platform with consciousness focus.",
        "funding_goal": 120000,
        "funding_raised": 0,
        "banner": "images/kure_academy/kureacademybannor.png",
        "logo": "images/kure_academy/kureacademylogo.png",
        "pdf_url": "pdf/kureacademywhitepaper.pdf",
        "whitepaper_preview": "Education redefined through consciousness studies.",
        "long_description": "An academy offering courses on mind and technology.",
        "stage": "Development",
        "market": "EdTech",
        "benefits": "6 months free access",
        "achievements": ["Pilot program launched", "Partnership with EduTech Inc"],
        "detail_endpoint": "kure_academy_details",
    },
    {
        "name": "PropertySolutionsAustralia (PSA)",
        "description": "Real estate investment and management app.",
        "funding_goal": 180000,
        "funding_raised": 0,
        "banner": "images/psa/psabannor2.png",
        "logo": "images/psa/psalogo.png",
        "pdf_url": "pdf/psa_placeholder.pdf",
        "whitepaper_preview": "Optimize property investments in Australia.",
        "long_description": "A tool for managing and growing real estate portfolios.",
        "stage": "Planning",
        "market": "Real Estate",
        "benefits": "Free consultation",
        "detail_endpoint": "property_solutions_australia_details",
    },
    {
        "name": "Zero Debt Solution",
        "description": "App to manage and eliminate debt.",
        "funding_goal": 50000000,
        "funding_raised": 0,
        "banner": "images/zde/zdebannor.png",
        "logo": "images/zde/zdelogo.jpg",
        "pdf_url": "pdf/ZeroDebtSolution(whitepaper).pdf",
        "whitepaper_preview": "Debt freedom tool for financial independence.",
        "long_description": "A financial app to help users achieve zero debt.",
        "stage": "Planning",
        "market": "Fintech",
        "benefits": "6 months free premium",
        "detail_endpoint": "zero_debt_solution_details",
    },
    {
        "name": "Patents",
        "description": "Support for patenting innovative ideas.",
        "funding_goal": 100000,
        "funding_raised": 0,
        "banner": "images/placeholder.png",
        "logo": "images/placeholder.png",
        "pdf_url": None,
        "whitepaper_preview": "Funding to secure patents for groundbreaking ideas.",
        "long_description": "Support the protection of intellectual property for future innovations.",
        "stage": "Planning",
        "market": "Legal Tech",
        "benefits": "Recognition as a patent supporter",
        "detail_endpoint": "ideas_details",
    },
    {
        "name": "Support Kyal",
        "description": "Direct support for the founder’s vision.",
        "funding_goal": 50000,
        "funding_raised": 0,
        "banner": "images/placeholder.png",
        "logo": "images/placeholder.png",
        "pdf_url": None,
        "whitepaper_preview": "Contribute to the founder’s mission to drive innovation.",
        "long_description": "Direct contributions to support Kyal’s leadership and vision.",
        "stage": "Ongoing",
        "market": "General",
        "benefits": "Personalized thank-you note",
        "detail_endpoint": "support_kyal",
    }
]

def get_ideas():
    return [
        {
            **idea,
            "pdf_url": url_for("static", filename=idea["pdf_url"]) if idea.get("pdf_url") else None,
            "banner": url_for("static", filename=idea["banner"]) if idea.get("banner") else None,
            "logo": url_for("static", filename=idea["logo"]) if idea.get("logo") else None,
        }
        for idea in raw_ideas
    ]

def get_total_raised_by_idea():
    try:
        # Load initial totals from totals.json as fallback
        totals_data = load_json(TOTALS_FILE, default={})
        total_raised_by_idea = {idea["name"]: totals_data.get(idea["name"], 0.0) for idea in raw_ideas}
        
        # Ensure EcoKure has at least $23,400 from NEIS funding
        total_raised_by_idea["EcoKure"] = max(total_raised_by_idea.get("EcoKure", 0.0), 23400.0)
        
        # Aggregate donations and investments from database
        for idea in raw_ideas:
            # Sum donations (in dollars, converted from cents)
            donations_sum = (
                db.session.query(db.func.coalesce(db.func.sum(Donation.amount), 0))
                .filter(Donation.idea == idea["name"])
                .scalar() or 0
            ) / 100.0
            # Sum investments (in dollars, converted from cents)
            investments_sum = (
                db.session.query(db.func.coalesce(db.func.sum(Investment.amount), 0))
                .filter(Investment.idea == idea["name"])
                .scalar() or 0
            ) / 100.0
            # Add to initial totals
            total_raised_by_idea[idea["name"]] += donations_sum + investments_sum
        
        # Save updated totals to totals.json
        save_json(TOTALS_FILE, total_raised_by_idea)
        return total_raised_by_idea
    except SQLAlchemyError as e:
        logger.error(f"Error calculating total_raised_by_idea: {str(e)}")
        # Fallback to totals.json if database query fails
        return totals_data if totals_data else {"EcoKure": 23400.0}

def get_total_raised():
    try:
        # Sum all totals from total_raised_by_idea
        total_raised_by_idea = get_total_raised_by_idea()
        return int(sum(total_raised_by_idea.values()))
    except Exception as e:
        logger.error(f"Error calculating total raised: {str(e)}")
        return 23400  # Fallback to minimum EcoKure NEIS funding

# --- Routes -----------------------------------------------------------------
@app.route("/")
def index():
    ideas = get_ideas()
    total_raised_by_idea = get_total_raised_by_idea()
    total_raised = get_total_raised()
    return render_template(
        "index.html",
        ideas=ideas,
        total_raised_by_idea=total_raised_by_idea,
        total_raised=total_raised,
        donations=Donation.query.order_by(Donation.timestamp.desc()).all(),
        investments=Investment.query.order_by(Investment.timestamp.desc()).all(),
        sponsors=load_json(SPONSORS_FILE),
        username=session.get("username"),
        stripe_publishable_key=app.config.get('STRIPE_PUBLISHABLE_KEY')
    )

@app.route("/about")
def about():
    return render_template("about.html", username=session.get("username"))

@app.route("/projects")
def projects():
    ideas = get_ideas()
    return render_template("projects.html", ideas=ideas, username=session.get("username"))

@app.route("/leaderboards")
def leaderboards():
    return render_template(
        "leaderboards.html",
        donations=Donation.query.order_by(Donation.amount.desc()).all(),
        investments=Investment.query.order_by(Investment.amount.desc()).all(),
        username=session.get("username")
    )

@app.route("/ideas")
def ideas_page():
    ideas = get_ideas()
    return render_template("ideas.html", ideas=ideas, username=session.get("username"))

@app.template_filter("spacify")
def spacify(text):
    if not text:
        return ""
    if "(" in text:
        main, rest = text.split("(", 1)
        main_spaced = re.sub(r"(?<!^)(?=[A-Z])", " ", main).strip()
        return f"{main_spaced} ({rest}"
    return re.sub(r"(?<!^)(?=[A-Z])", " ", text).strip()

@app.route("/join-ecosystem")
def join_ecosystem():
    return render_template("join_ecosystem.html", username=session.get("username"))

# --- Auth Routes ------------------------------------------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Check for missing fields
        if not all([username, email, password, confirm_password]):
            flash("All fields are required.", "error")
            return redirect(url_for("signup"))

        # Password validation rules
        errors = []
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter.")
        if not re.search(r'[0-9]', password):
            errors.append("Password must contain at least one number.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character (e.g., !@#$%^&*).")
        if password != confirm_password:
            errors.append("Passwords do not match.")

        if errors:
            for error in errors:
                flash(error, "error")
            return redirect(url_for("signup"))

        # Check for duplicate username or email
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "error")
            return redirect(url_for("signup"))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return redirect(url_for("signup"))

        try:
            user = User(username=username, email=email, password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            login_user(user)
            session["username"] = user.username
            flash("Account created successfully!", "success")
            return redirect(url_for("index"))
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            db.session.rollback()
            flash("Error creating account. Please try again.", "error")
            return redirect(url_for("signup"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password")
        if not identifier or not password:
            flash("Username or email and password are required.", "error")
            return redirect(url_for("login"))

        try:
            user = User.query.filter_by(username=identifier).first() or \
                   User.query.filter_by(email=identifier.lower()).first()
            if not user:
                flash("Username or email not found.", "error")
                return redirect(url_for("login"))

            if not user.password_hash:
                flash("Account setup incomplete. Please contact support.", "error")
                return redirect(url_for("login"))

            if check_password_hash(user.password_hash, password):
                login_user(user)
                session["username"] = user.username
                flash("Logged in successfully!", "success")
                return redirect(url_for("index"))

            flash("Incorrect password.", "error")
            return redirect(url_for("login"))

        except Exception as e:
            logger.error(f"Login error: {e}")
            flash("Login error. Please try again.", "error")
            return redirect(url_for("login"))

    return render_template("login.html", username=session.get("username"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("username", None)
    flash("Logged out successfully.", "success")
    return redirect(url_for("index"))

# --- Debug Routes -----------------------------------------------------------
@app.route("/clear-session")
def clear_session():
    session.clear()
    logout_user()
    flash("Session cleared. Please log in again.", "info")
    return redirect(url_for("login"))

@app.route("/debug-user/<int:user_id>")
@login_required
def debug_user(user_id):
    if current_user.id != user_id:
        logger.error(f"Unauthorized access to debug-user for user_id: {user_id} by user: {current_user.id}")
        return jsonify({"error": "Unauthorized"}), 403
    try:
        donations = Donation.query.filter_by(user_id=user_id).all()
        investments = Investment.query.filter_by(user_id=user_id).all()
        subscription = Subscription.query.filter_by(user_id=user_id).first()
        return jsonify({
            "donations": [{"id": d.id, "idea": d.idea, "amount": d.amount/100, "message": d.message, "timestamp": d.timestamp.isoformat()} for d in donations],
            "investments": [{"id": i.id, "idea": i.idea, "amount": i.amount/100, "timestamp": i.timestamp.isoformat()} for i in investments],
            "subscription": {"plan": subscription.plan, "status": subscription.status, "next_billing": subscription.next_billing.isoformat() if subscription and subscription.next_billing else None} if subscription else None
        })
    except Exception as e:
        logger.error(f"Debug error for user {user_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "healthy", "database": "connected"})
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

# --- Create Stripe Customer -----------------------------------------------
@app.route("/create-customer", methods=["POST"])
def create_customer():
    data = request.get_json()
    email = data.get('email')
    name = data.get('name', 'Anonymous')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    # Check for existing customer
    existing_customers = stripe.Customer.list(email=email).data
    if existing_customers:
        customer = existing_customers[0]
        logger.info(f"Stripe customer already exists: {customer.id} for email: {email}")
        return jsonify({'customer_id': customer.id})

    try:
        customer = stripe.Customer.create(
            email=email,
            name=name
        )
        logger.info(f"Created Stripe customer: {customer.id} for email: {email}")
        return jsonify({'customer_id': customer.id})
    except stripe.error.StripeError as e:
        logger.error(f"Error creating Stripe customer: {e}")
        return jsonify({'error': str(e)}), 400

# --- Create PaymentIntent -------------------------------------------------
@app.route("/create-payment-intent", methods=["POST"])
def create_payment_intent():
    data = request.get_json()
    try:
        # Validate amount
        amount = float(data.get("amount", 0))
        if amount < 0.50:
            return jsonify({"error": "Amount must be at least $0.50"}), 400
        amount_cents = int(amount * 100)

        # Determine email and user
        if current_user.is_authenticated:
            email = current_user.email
            user_id = current_user.id
            name = current_user.username
        else:
            email = data.get("email")
            if not email:
                return jsonify({"error": "Email is required"}), 400
            user_id = None
            name = data.get("name", "Anonymous")

        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency="aud",
            automatic_payment_methods={"enabled": True},
            metadata={
                "user_id": str(user_id) if user_id else "",
                "name": name,
                "email": email,
                "action": data.get("action", "Donate"),
                "idea": data.get("idea", "General"),
                "recurrence": data.get("recurrence", "once"),
                "message": data.get("message", "")
            }
        )
        return jsonify({"clientSecret": intent.client_secret})
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error creating PaymentIntent: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Server error creating PaymentIntent: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- Stripe Webhook -------------------------------------------------------
@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, app.config.get("STRIPE_WEBHOOK_SECRET")
        )
    except ValueError:
        logger.error("Invalid webhook payload")
        return jsonify({"error": "Invalid payload"}), 400
    except stripe.error.SignatureVerificationError:
        logger.error("Invalid webhook signature")
        return jsonify({"error": "Invalid signature"}), 400

    try:
        if event["type"] == "payment_intent.succeeded":
            payment_intent = event["data"]["object"]
            metadata = payment_intent.get("metadata", {})
            user_id = metadata.get("user_id")
            action = metadata.get("action", "Donate")
            idea = metadata.get("idea", "General")
            message = metadata.get("message", "")
            amount = payment_intent["amount"]  # cents

            user = User.query.get(int(user_id)) if user_id else None
            logger.info(f"Webhook: Processing payment for user: {user.username if user else 'Guest'}, action: {action}")

            if action.lower() == "invest" and user:
                investment = Investment(
                    user_id=user.id,
                    idea=idea,
                    amount=amount,
                    timestamp=datetime.now(timezone.utc)
                )
                db.session.add(investment)
                logger.info(f"{user.username} invested ${amount/100} in {idea}")
            else:
                donation = Donation(
                    user_id=user.id if user else None,
                    idea=idea,
                    amount=amount,
                    message=message,
                    timestamp=datetime.now(timezone.utc)
                )
                db.session.add(donation)
                logger.info(f"{metadata.get('name', 'Guest')} donated ${amount/100} to {idea}")

            db.session.commit()
            # Update totals.json after successful payment
            total_raised_by_idea = get_total_raised_by_idea()
            total_raised_by_idea[idea] = total_raised_by_idea.get(idea, 0.0) + (amount / 100.0)
            save_json(TOTALS_FILE, total_raised_by_idea)
            logger.info(f"Webhook: Successfully saved {action} for payment_intent: {payment_intent['id']}")

        return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.error(f"Webhook processing error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Webhook processing failed"}), 500

# --- Cancel Subscription --------------------------------------------------
@app.route("/cancel-subscription", methods=["POST"])
def cancel_subscription():
    data = request.get_json()
    subscription_id = data.get('subscriptionId')
    try:
        if not subscription_id:
            logger.error("No subscription ID provided for cancellation")
            return jsonify({'error': 'No subscription ID provided'}), 400
        deleted_subscription = stripe.Subscription.delete(subscription_id)
        sub = Subscription.query.filter_by(stripe_subscription_id=subscription_id).first()
        if sub:
            sub.status = 'canceled'
            db.session.commit()
            logger.info(f"Canceled subscription: {subscription_id}")
        return jsonify({'status': 'success'})
    except stripe.error.StripeError as e:
        logger.error(f"Error canceling subscription: {e}")
        return jsonify({'error': str(e)}), 400

# --- Invest Page ----------------------------------------------------------
@app.route("/invest", methods=["GET", "POST"])
def invest():
    ideas = get_ideas()
    if request.method == "POST":
        idea_name = request.form.get("idea", "").strip()
        try:
            amount = float(request.form.get("amount"))
        except ValueError:
            flash("Invalid amount.", "error")
            return redirect(url_for("invest"))

        if amount < 0.50:
            flash("Amount must be at least $0.50", "error")
            return redirect(url_for("invest"))

        if not current_user.is_authenticated:
            flash("Please log in to invest.", "error")
            return redirect(url_for("login"))

        # Redirect to Stripe Checkout for monthly subscription
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="subscription",  # recurring monthly payment
                line_items=[{
                    "price_data": {
                        "currency": "aud",
                        "product_data": {"name": f"Investment in {idea_name}"},
                        "unit_amount": int(amount * 100),  # Stripe expects cents
                        "recurring": {"interval": "month"}
                    },
                    "quantity": 1,
                }],
                metadata={"user_id": current_user.id, "idea": idea_name, "action": "Invest"},
                success_url=url_for("return_page", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=url_for("invest", _external=True),
                customer_email=current_user.email
            )
            return redirect(checkout_session.url, code=303)
        except Exception as e:
            logger.exception(f"Stripe Checkout error: {e}")
            flash("Error initiating payment. Please try again.", "error")
            return redirect(url_for("invest"))

    return render_template(
        "invest.html",
        ideas=ideas,
        username=current_user.username if current_user.is_authenticated else None,
        stripe_publishable_key=app.config.get('STRIPE_PUBLISHABLE_KEY')
    )

# --- Donate Page ----------------------------------------------------------
@app.route("/donate", methods=["GET", "POST"])
def donate():
    customer_id = request.args.get('customer_id') or request.form.get('customer_id')
    if request.method == "POST":
        amount = request.form.get("amount", type=float)
        message = request.form.get("message", "No message")
        idea = request.form.get("idea", "General")

        if not amount or amount <= 0:
            flash("Invalid donation amount.", "error")
            return redirect(url_for("donate"))

        # Stripe Checkout one-time payment for donation
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="payment",  # one-time payment
                line_items=[{
                    "price_data": {
                        "currency": "aud",
                        "product_data": {"name": f"Donation to {idea}"},
                        "unit_amount": int(amount * 100),
                    },
                    "quantity": 1,
                }],
                metadata={"user_id": getattr(current_user, "id", None), "idea": idea, "action": "Donate", "message": message},
                success_url=url_for("return_page", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=url_for("donate", _external=True),
                customer_email=getattr(current_user, "email", None) or request.form.get("guest_email")
            )
            return redirect(checkout_session.url, code=303)
        except Exception as e:
            logger.exception(f"Stripe donation checkout error: {e}")
            flash("Error initiating donation payment. Please try again.", "error")
            return redirect(url_for("donate"))

    return render_template(
        "donate.html",
        ideas=get_ideas(),
        customer_id=customer_id,
        username=session.get("username"),
        stripe_publishable_key=app.config.get('STRIPE_PUBLISHABLE_KEY')
    )

# --- Subscribe Route ------------------------------------------------------
@app.route("/subscribe", methods=["POST"])
@login_required
def subscribe():
    try:
        email = request.form.get("email") or current_user.email
        plan_amount = request.form.get("amount", type=float)

        if not plan_amount or plan_amount < 0.50:
            flash("Please select a valid subscription amount.", "error")
            return redirect(url_for("profile"))

        # Create Stripe subscription for monthly recurring payment
        stripe_customer = stripe.Customer.create(email=email, name=current_user.username)

        price_data = stripe.Price.create(
            unit_amount=int(plan_amount * 100),
            currency="aud",
            recurring={"interval": "month"},
            product_data={"name": f"{current_user.username}'s Monthly Subscription"}
        )

        checkout_session = stripe.checkout.Session.create(
            customer=stripe_customer.id,
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": price_data.id, "quantity": 1}],
            success_url=url_for("return_page", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("profile", _external=True)
        )

        return redirect(checkout_session.url, code=303)

    except Exception as e:
        logger.error(f"Subscription error for user {current_user.username}: {str(e)}")
        flash(f"Error creating subscription: {str(e)}", "error")
        return redirect(url_for("profile"))

# --- Email Subscription Handler ---
@app.route("/subscribe_email", methods=["POST"])
@login_required
def subscribe_email():
    try:
        email = current_user.email
        subscription_type = request.form.get("subscription_type", "Email")

        # Create or update subscription record
        subscription = Subscription.query.filter_by(user_id=current_user.id).first()
        if not subscription:
            subscription = Subscription(user_id=current_user.id, email=email)
            db.session.add(subscription)

        subscription.plan = subscription_type
        subscription.status = "Active"
        subscription.created_at = subscription.created_at or datetime.now(timezone.utc)

        # Update user email subscription flag
        current_user.subscribed_email = True

        db.session.commit()
        flash("Email subscription updated successfully!", "success")
        return redirect(url_for("profile"))
    except Exception as e:
        logger.error(f"Error updating email subscription for user {current_user.username}: {str(e)}")
        flash(f"Error updating email subscription: {str(e)}", "error")
        return redirect(url_for("profile"))

# --- Unsubscribe Handler ---
@app.route("/unsubscribe", methods=["POST"])
@login_required
def unsubscribe():
    try:
        unsubscribe_type = request.form.get("type")
        subscription = Subscription.query.filter_by(user_id=current_user.id).first()

        if unsubscribe_type == "email":
            current_user.subscribed_email = False
            if subscription and subscription.plan.lower() == "email":
                db.session.delete(subscription)
            db.session.commit()
            flash("You have unsubscribed from email updates.", "success")
        elif unsubscribe_type == "monthly":
            if subscription:
                db.session.delete(subscription)
                db.session.commit()
                flash("Subscription successfully canceled!", "success")
            else:
                flash("No active paid subscription found.", "error")
        else:
            flash("Invalid unsubscribe request.", "error")

        return redirect(url_for("profile"))
    except Exception as e:
        logger.error(f"Error unsubscribing for user {current_user.username}: {str(e)}")
        flash(f"Error unsubscribing: {str(e)}", "error")
        return redirect(url_for("profile"))

# --- Placeholder Stripe Payment Function ---
def stripe_payment(amount, email):
    # Replace with real Stripe API call
    print(f"Charging {email} an amount of {amount}")
    return True

# --- Return Page -----------------------------------------------------------
@app.route("/return")
def return_page():
    session_id = request.args.get('session_id')
    try:
        session = stripe.Checkout.Session.retrieve(session_id)
        if session.payment_status == 'paid':
            action = session.metadata.get('action', 'Contribution')
            idea = session.metadata.get('idea', 'General')
            flash(f"{action} to {idea} successful! Thank you for your support.", "success")
        else:
            flash("Payment not completed. Please try again.", "error")
    except stripe.error.StripeError as e:
        logger.error(f"Error retrieving checkout session: {e}")
        flash("Error verifying payment. Please contact support.", "error")
    return render_template("return.html")

# --- Profile Page ----------------------------------------------------------
@app.route("/profile")
@login_required
def profile():
    try:
        user = db.session.get(User, current_user.id)
        if not user:
            session.clear()
            flash("User not found. Please log in again.", "error")
            return redirect(url_for("login"))

        # Fetch user donations and investments
        donations = Donation.query.filter_by(user_id=user.id).order_by(Donation.timestamp.desc()).all()
        investments = Investment.query.filter_by(user_id=user.id).order_by(Investment.timestamp.desc()).all()

        # Fetch active subscription
        subscription = Subscription.query.filter_by(user_id=user.id, status="Active").first()

        return render_template(
            "profile.html",
            current_user=user,
            donations=donations or [],
            investments=investments or [],
            subscription=subscription,
            email_subscribed=user.subscribed_email
        )
    except Exception as e:
        logger.error(f"Error loading profile for user {current_user.username}: {str(e)}")
        flash("Error loading profile. Please try again.", "error")
        return redirect(url_for("login"))

# --- API --------------------------------------------------------------------
@app.route("/total-raised")
def get_total_raised_json():
    return jsonify({"total_raised": get_total_raised()})

# --- Project + Detail Pages -------------------------------------------------
@app.route("/property_solutions_australia")
def property_solutions_australia():
    return render_template("property_solutions_australia_details.html")

@app.route("/kure_mechanics")
def kure_mechanics():
    return render_template("kure_mechanics_details.html")

@app.route("/kure_academy")
def kure_academy():
    return render_template("kure_academy_details.html")

@app.route("/jarvi3")
def jarvi3():
    return render_template("jarvi3_details.html")

@app.route("/ecokure")
def ecokure():
    return render_template("ecokure_details.html")

@app.route("/quantum_system_lock")
def quantum_system_lock():
    return render_template("quantum_system_lock_details.html")

@app.route("/zero_debt_solution")
def zero_debt_solution():
    return render_template("zero_debt_solution_details.html")

@app.route("/home_details")
def home_details():
    return render_template("home_details.html")

@app.route("/about_details")
def about_details():
    return render_template("about_details.html")

@app.route("/ideas_details")
def ideas_details():
    return render_template("ideas_details.html")

@app.route("/invest_details")
def invest_details():
    return render_template("invest_details.html")

@app.route("/property_solutions_australia_details")
def property_solutions_australia_details():
    return render_template("property_solutions_australia_details.html")

@app.route("/kure_mechanics_details")
def kure_mechanics_details():
    return render_template("kure_mechanics_details.html")

@app.route("/kure_academy_details")
def kure_academy_details():
    return render_template("kure_academy_details.html")

@app.route("/jarvi3_details")
def jarvi3_details():
    return render_template("jarvi3_details.html")

@app.route("/ecokure_details")
def ecokure_details():
    return render_template("ecokure_details.html")

@app.route("/support_kyal")
def support_kyal():
    return render_template("support_kyal.html")

@app.route("/quantum_system_lock_details")
def quantum_system_lock_details():
    return render_template("quantum_system_lock_details.html")

@app.route("/zero_debt_solution_details")
def zero_debt_solution_details():
    return render_template("zero_debt_solution_details.html")

@app.route("/join-a-team")
def join_a_team():
    ideas = get_ideas()
    total_raised = get_total_raised()
    return render_template(
        "join_a_team.html",
        ideas=ideas,
        donations=Donation.query.order_by(Donation.timestamp.desc()).all(),
        investments=Investment.query.order_by(Investment.amount.desc()).all(),
        sponsors=load_json(SPONSORS_FILE),
        total_raised=total_raised,
    )

# --- App bootstrap ----------------------------------------------------------
with app.app_context():
    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.info("Checking database initialization...")
            inspector = inspect(db.engine)
            if not inspector.get_table_names():
                logger.info("Initializing database schema...")
                db.create_all()
                migrate_json_to_db()
            else:
                logger.info("Database schema already exists")
                ensure_database_schema()  # Ensure schema is up-to-date
            # Verify database connectivity
            db.session.execute(text("SELECT 1"))
            logger.info("Database connection established at startup")
            break
        except OperationalError as e:
            logger.error(f"Database initialization failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
            if attempt == max_retries - 1:
                raise RuntimeError(f"Failed to initialize database after {max_retries} attempts: {str(e)}")
            time.sleep(1)  # Wait before retrying
        except Exception as e:
            logger.error(f"Unexpected error during database initialization: {str(e)}")
            raise

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
