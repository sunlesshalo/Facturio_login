import base64         # For encoding/decoding strings
import logging        # For logging messages (debugging, errors)
import requests       # For making HTTP requests to external APIs
import json           # For working with JSON data
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from replit import db  # Replit's built-in simple database

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Used to sign session cookies; replace with a strong secret

# Fixed parameters for SmartBill API calls
SMARTBILL_BASE_URL = "https://ws.smartbill.ro/SBORO/api/"
SMARTBILL_SERIES_TYPE = "f"  # Default series type

# Configure logging to help us understand what's happening in the code
logging.basicConfig(
    level=logging.DEBUG,  # Log all messages at DEBUG level and higher
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

def get_smartbill_auth_header(username, token):
    """
    Creates an HTTP Basic Authentication header required by SmartBill.
    It combines the username and token into a single string "username:token",
    encodes it using Base64, and returns a dictionary that can be used as HTTP headers.
    """
    auth_string = f"{username}:{token}"
    encoded_auth = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
    header = {"Authorization": f"Basic {encoded_auth}"}
    logger.debug("Constructed Auth Header: %s", header)
    return header

# -------------------- Onboarding API Endpoints --------------------

@app.route("/", methods=["GET"])
def index():
    """
    The home page. This page contains the SmartBill onboarding form.
    The JavaScript in the page handles the form submission via AJAX.
    """
    return render_template("index.html")

@app.route("/api/get_series", methods=["POST"])
def api_get_series():
    """
    This endpoint expects a JSON payload with:
      - smartbill_email: the user's SmartBill email (username)
      - smartbill_token: the SmartBill API token
      - cif: the company's tax code (used as password)
    It calls the SmartBill API and returns the invoice series from the "list" key.
    """
    data = request.get_json()
    smartbill_email = data.get("smartbill_email", "").strip()
    smartbill_token = data.get("smartbill_token", "").strip()
    cif = data.get("cif", "").strip()

    if not smartbill_email or not smartbill_token or not cif:
        logger.warning("Missing required fields in JSON payload.")
        return jsonify({"status": "error", "message": "Toate câmpurile sunt obligatorii"}), 400

    series_url = f"{SMARTBILL_BASE_URL}series"
    headers = {"Content-Type": "application/json"}
    headers.update(get_smartbill_auth_header(smartbill_email, smartbill_token))
    params = {"cif": cif, "type": SMARTBILL_SERIES_TYPE}

    logger.debug("Sending GET request to %s", series_url)
    logger.debug("Headers: %s", headers)
    logger.debug("Parameters: %s", params)

    try:
        response = requests.get(series_url, headers=headers, params=params)
        logger.debug("Received response with status code: %s", response.status_code)
        logger.debug("Response text: %s", response.text)
        response.raise_for_status()
        resp_data = response.json()
        logger.debug("Parsed JSON: %s", resp_data)
    except requests.exceptions.HTTPError as errh:
        logger.error("HTTP Error: %s", errh)
        return jsonify({"status": "error", "message": f"Eroare HTTP: {errh}"}), response.status_code if response else 500
    except requests.exceptions.RequestException as err:
        logger.error("Request Exception: %s", err)
        return jsonify({"status": "error", "message": f"Eroare de conexiune: {err}"}), 500
    except ValueError as errv:
        logger.error("JSON parsing error: %s", errv)
        return jsonify({"status": "error", "message": "Răspuns invalid din partea SmartBill"}), 500

    # Extract the invoice series from the "list" key in the response.
    series_list = resp_data.get("list", [])
    logger.debug("Extracted series list: %s", series_list)
    if not series_list:
        logger.warning("No invoice series found in response.")
        return jsonify({"status": "error", "message": "Nu s-au găsit serii de facturare."}), 404

    return jsonify({"status": "success", "series_list": series_list}), 200

@app.route("/api/set_default_series", methods=["POST"])
def api_set_default_series():
    """
    This endpoint expects a JSON payload with:
      - smartbill_email: the user's SmartBill email
      - default_series: the chosen invoice series
      Optionally, it can also include 'cif' (company tax code) to create a user record.
    It saves the default series in the database.
    Additionally, if a company tax code is provided, it creates a user record.
    """
    data = request.get_json()
    smartbill_email = data.get("smartbill_email", "").strip()
    default_series = data.get("default_series", "").strip()
    cif = data.get("cif", "").strip()  # Optional field for password

    if not smartbill_email or not default_series:
        return jsonify({"status": "error", "message": "Missing parameters"}), 400

    # Save the default invoice series for the user.
    db[f"default_series:{smartbill_email}"] = default_series
    logger.info("Default series saved for %s: %s", smartbill_email, default_series)

    # If the company tax code (CIF) is provided, create a user record.
    if cif:
        user_key = f"user:{smartbill_email}"
        if user_key not in db:
            user_record = {"email": smartbill_email, "password": cif}
            db[user_key] = json.dumps(user_record)
            logger.info("User record created for %s", smartbill_email)

    return jsonify({"status": "success", "default_series": default_series}), 200

@app.route("/api/stripe_create_webhook", methods=["POST"])
def stripe_create_webhook():
    """
    This endpoint expects a JSON payload with:
      - stripe_key: the Stripe API key provided by the user
    It uses the stripe_key to create a new webhook endpoint on Stripe that listens for the event "checkout.session.completed"
    and has the description "Facturio Early Adopter Program". The webhook URL is built using the INSTANCE_URL environment variable.
    The returned webhook 'id' and 'secret' are then stored in the database.
    """
    data = request.get_json()
    stripe_key = data.get("stripe_key", "").strip()

    if not stripe_key:
        return jsonify({"status": "error", "message": "Missing stripe_key"}), 400

    import os
    instance_url = os.environ.get("INSTANCE_URL")
    if not instance_url:
        logger.error("INSTANCE_URL environment variable is not set.")
        return jsonify({"status": "error", "message": "INSTANCE_URL not set"}), 500

    # Build the full webhook URL from the INSTANCE_URL
    webhook_url = f"{instance_url}/stripe-webhook"
    logger.debug("Using webhook URL: %s", webhook_url)

    import stripe
    stripe.api_key = stripe_key
    try:
        webhook = stripe.WebhookEndpoint.create(
            enabled_events=["checkout.session.completed"],
            url=webhook_url,
            description="Facturio Early Adopter Program"
        )
        # Extract the webhook "id" and "secret"
        webhook_data = {
            "id": webhook.get("id"),
            "secret": webhook.get("secret")
        }
        # Store the webhook data in the database.
        db["stripe_webhook"] = json.dumps(webhook_data)
        logger.info("Stripe webhook created and stored: %s", webhook_data)
        return jsonify({"status": "success", "webhook": webhook_data}), 200
    except Exception as e:
        logger.error("Stripe webhook creation error: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500

# -------------------- Login, Logout, and Dashboard Endpoints --------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    The login page:
      - GET: Displays the login form.
      - POST: Processes the login form.
    The user enters their Facturio username (SmartBill email) and password (company tax code).
    If the credentials match a user record in the database, the user is logged in.
    If the user hasn't completed onboarding (missing default series), they are redirected to the onboarding page.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        # Retrieve the user record from the database.
        user_key = f"user:{email}"
        if user_key not in db:
            flash("Utilizatorul nu există. Vă rugăm să completați onboarding-ul.")
            return redirect(url_for("login"))
        user_record = json.loads(db[user_key])
        # Check if the entered password (company tax code) matches the stored password.
        if password != user_record.get("password"):
            flash("Parola incorectă!")
            return redirect(url_for("login"))

        # Check if onboarding is complete (i.e., default series is set).
        if f"default_series:{email}" not in db:
            flash("Onboarding incomplet! Vă rugăm să finalizați onboarding-ul SmartBill.")
            return redirect(url_for("index"))

        # Set the user email in session to mark the user as logged in.
        session["user_email"] = email
        flash("Logare cu succes!")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    """
    Logs the user out by clearing the session and redirects to the login page.
    """
    session.clear()
    flash("Ați fost deconectat.")
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    """
    The dashboard page, which is shown only to logged-in users.
    It displays:
      - A success message (e.g., "Conectat la SmartBill cu success: ...")
      - The user's SmartBill username (as "Nume utilizator")
      - The company tax code ("CUI")
      - A logout button
      - A "Schimbare parola" link to change the password.
    If the user is not logged in, they are redirected to the login page.
    """
    email = session.get("user_email")
    if not email:
        flash("Vă rugăm să vă logați.")
        return redirect(url_for("login"))

    # Retrieve default series and user info from the database.
    default_series = db.get(f"default_series:{email}", "N/A")
    user_key = f"user:{email}"
    user_record = json.loads(db[user_key]) if user_key in db else {}
    cui = user_record.get("password", "N/A")  # In this app, the password is the company tax code

    return render_template("dashboard.html", email=email, cui=cui, default_series=default_series)

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """
    Allows a logged-in user to change their password (company tax code).
    GET: Displays the change password form.
    POST: Processes the form, updates the user record, and shows a success message.
    """
    email = session.get("user_email")
    if not email:
        flash("Vă rugăm să vă logați.")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        if not new_password:
            flash("Vă rugăm să introduceți o parolă nouă.")
            return redirect(url_for("change_password"))

        user_key = f"user:{email}"
        if user_key in db:
            user_record = json.loads(db[user_key])
            user_record["password"] = new_password
            db[user_key] = json.dumps(user_record)
            flash("Parola a fost actualizată cu succes!")
            return redirect(url_for("dashboard"))
        else:
            flash("Utilizatorul nu există.")
            return redirect(url_for("login"))

    return render_template("change_password.html")

@app.route("/status")
def status():
    """
    A simple endpoint to verify that the app is running.
    """
    return "Onboarding SmartBill App is running."

if __name__ == "__main__":
    # Run the app on port 8080 (Replit default).
    app.run(host="0.0.0.0", port=8080)
