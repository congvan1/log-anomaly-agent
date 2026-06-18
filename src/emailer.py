"""Send the report by email (OPTIONAL).

Disabled by default. Enable with the --email flag + SMTP config via env vars:
  SMTP_HOST, SMTP_PORT (465 SSL), SMTP_USER, SMTP_PASS, EMAIL_FROM, EMAIL_TO

For Gmail: create an App Password (https://myaccount.google.com/apppasswords)
and set SMTP_USER = your Gmail address, SMTP_PASS = the 16-char App Password.
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage


def send_report(*, subject: str, body_text: str, html_path: str,
                to_addr: str | None = None) -> str:
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "465"))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")
    sender = os.environ.get("EMAIL_FROM", user or "")
    recipient = to_addr or os.environ.get("EMAIL_TO", "bon@thinksmartinsurance.com")

    if not user or not password:
        return ("SKIP: SMTP_USER/SMTP_PASS not configured — skipping email. "
                f"(report is ready to send manually to {recipient})")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.set_content(body_text)

    with open(html_path, "rb") as fh:
        data = fh.read()
    msg.add_attachment(data, maintype="text", subtype="html",
                       filename=os.path.basename(html_path))

    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(host, port, context=ctx) as srv:
        srv.login(user, password)
        srv.send_message(msg)
    return f"OK: report sent to {recipient}"
