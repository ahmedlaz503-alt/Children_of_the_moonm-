import os, re, secrets, smtplib, hmac, time
import psycopg
from collections import defaultdict, deque
from functools import wraps
from email.message import EmailMessage
from flask import Flask, request, render_template, redirect, url_for, flash, abort, session

APP = Flask(__name__)
APP.config.update(
    SECRET_KEY=os.environ.get("APP_SECRET", "local-development-only-change-before-deploy"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=16 * 1024,
)
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000").rstrip("/")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
CONTACT_EMAIL = "ahmedlaz503@gmail.com"

_requests = defaultdict(deque)
def limit_subscribe(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        now = time.time()
        bucket = _requests[request.remote_addr or "unknown"]
        while bucket and now - bucket[0] > 3600:
            bucket.popleft()
        if len(bucket) >= 5:
            abort(429)
        bucket.append(now)
        return fn(*args, **kwargs)
    return wrapped


def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(
        DATABASE_URL,
        hostaddr=os.environ.get("DB_HOSTADDR", "18.202.64.2"),
        sslmode="require",
        connect_timeout=20
    )


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]

APP.jinja_env.globals["csrf_token"] = csrf_token


def valid_email(value):
    return len(value) <= 254 and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value or "") is not None


def send_email(to, subject, body, unsubscribe_url=None):
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, FROM_EMAIL]):
        raise RuntimeError("SMTP is not configured")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL
    msg["To"] = to
    if unsubscribe_url:
        msg["List-Unsubscribe"] = f"<{unsubscribe_url}>"
        msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)


@APP.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response


@APP.get("/")
def home():
    return render_template("index.html")


@APP.post("/subscribe")
@limit_subscribe
def subscribe():
    supplied_csrf = request.form.get("csrf", "")
    if not hmac.compare_digest(supplied_csrf, session.get("csrf", "")):
        abort(400)
    # Honeypot: humans leave this hidden field empty.
    if request.form.get("website", "").strip():
        return redirect(url_for("home"))
    email = request.form.get("email", "").strip().lower()
    if not valid_email(email) or request.form.get("consent") != "yes":
        flash("يرجى إدخال بريد صحيح والموافقة الصريحة على استقبال التحديثات.")
        return redirect(url_for("home"))

    token, unsub = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    c = db()
    try:
        c.execute("INSERT INTO subscribers(email, confirm_token, unsubscribe_token) VALUES(%s,%s,%s)", (email, token, unsub))
        c.commit()
    except psycopg.errors.UniqueViolation:
        c.close()
        flash("هذا البريد مسجل مسبقاً. إذا لم تؤكد اشتراكك، افحص رسالة التأكيد.")
        return redirect(url_for("home"))
    c.close()

    confirm_url = f"{BASE_URL}/confirm/{token}"
    unsubscribe_url = f"{BASE_URL}/unsubscribe/{unsub}"
    try:
        send_email(email, "أكد اشتراكك | أبناء القمر",
                   "شكراً لاهتمامك بمشروع أبناء القمر.\n\nأكد رغبتك في استقبال التحديثات عبر الرابط التالي:\n"
                   + confirm_url + "\n\nإذا لم تطلب هذا الاشتراك، فتجاهل الرسالة.\nإلغاء الاشتراك: " + unsubscribe_url,
                   unsubscribe_url)
        flash("أرسلنا رسالة تأكيد. افتح بريدك واضغط رابط التأكيد.")
    except Exception:
        # Keep the pending record, but never claim a message was sent.
        APP.logger.exception("Confirmation email could not be sent")
        flash("تم حفظ طلبك مؤقتاً، لكن البريد غير مهيأ حالياً. لم يتم تأكيد الاشتراك.")
    return redirect(url_for("home"))


@APP.route("/confirm/<token>", methods=["GET", "POST"])
def confirm(token):
    if request.method == "GET":
        return render_template("confirm_subscription.html", token=token)

    supplied_csrf = request.form.get("csrf", "")
    if not hmac.compare_digest(supplied_csrf, session.get("csrf", "")):
        abort(400)

    if not hmac.compare_digest(request.form.get("token", ""), token):
        abort(400)

    c = db()
    cur = c.execute(
        "UPDATE subscribers SET confirmed=TRUE, confirmed_at=CURRENT_TIMESTAMP "
        "WHERE confirm_token=%s AND confirmed=FALSE",
        (token,)
    )
    c.commit()
    ok = cur.rowcount == 1
    c.close()

    return render_template(
        "result.html",
        title="تم تأكيد الاشتراك" if ok else "الرابط غير صالح أو سبق استخدامه",
        message="شكراً. ستصلك تحديثات أبناء القمر، ويمكنك إلغاء الاشتراك في أي وقت."
        if ok else "تعذر تأكيد هذا الرابط."
    )


@APP.route("/unsubscribe/<token>", methods=["GET", "POST"])
def unsubscribe(token):
    if request.method == "GET":
        return render_template("unsubscribe_confirm.html", token=token)

    # دعم إلغاء الاشتراك بضغطة واحدة من مزودي البريد.
    one_click = request.form.get("List-Unsubscribe") == "One-Click"

    if not one_click:
        supplied_csrf = request.form.get("csrf", "")
        if not hmac.compare_digest(supplied_csrf, session.get("csrf", "")):
            abort(400)
        if not hmac.compare_digest(request.form.get("token", ""), token):
            abort(400)

    c = db()
    cur = c.execute(
        "DELETE FROM subscribers WHERE unsubscribe_token=%s",
        (token,)
    )
    c.commit()
    ok = cur.rowcount == 1
    c.close()

    return render_template(
        "result.html",
        title="تم إلغاء الاشتراك" if ok else "الرابط غير صالح",
        message="لن تصلك رسائل أخرى من هذه القائمة."
        if ok else "تعذر العثور على الاشتراك."
    )


@APP.get("/privacy")
def privacy():
    return render_template("result.html", title="سياسة الخصوصية",
        message="نستخدم بريدك فقط لإرسال أخبار وتحديثات مشروع أبناء القمر بعد موافقتك وتأكيد اشتراكك. لا نبيع بياناتك. يمكنك إلغاء الاشتراك من رابط الإلغاء في الرسائل أو التواصل عبر " + CONTACT_EMAIL + ".")


@APP.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    db().close()
    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
