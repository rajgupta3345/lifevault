# LifeVault

LIFEVault is a local-first Python desktop application for personal document management and emergency readiness.

## Main features
- Local registration and sign-in with salted PBKDF2-HMAC-SHA256 password hashes.
- Encrypted document attachments using Fernet; a file attachment is optional.
- A random vault key protected by both the master password and recovery code.
- Local recovery-code password reset that preserves encrypted documents; no email reset is claimed.
- Document search, category/status filters, and Active / Expiring Soon / Expired tracking.
- Emergency contacts, editable emergency profile, Emergency Pack, and Emergency Mode.
- Project-defined readiness score, activity log, fictional demo data, and 15-minute inactivity lock.
- Optional Google Desktop OAuth identity verification. A local master password remains necessary to unlock the vault.

## Install and run
Requires Python 3.11 or newer. In PowerShell or Command Prompt, from this folder:

    python -m pip install -r requirements.txt
    python main.py

On Windows, double-click Run_LifeVault.bat to check Python, install dependencies, and launch the app.

Save the recovery code shown once during account creation. Losing both it and the master password means the encrypted vault cannot be recovered. For a presentation, choose Settings -> Load Demo Data; all sample people and documents are fictional.

## Google sign-in
Google OAuth is optional. Create a Google OAuth Client ID with application type Desktop app, download the JSON as credentials.json, and place it beside main.py. See Google_Login_Setup.txt. The app requests only OpenID, email, and basic profile identity; it does not request Gmail, Drive, or Contacts scopes. If credentials.json is absent, the app displays setup guidance and local login still works.

## Project note
This is a college/local prototype, not a production security, medical, legal, or emergency-response product. SQLite metadata and temporary opened copies are not encrypted by this prototype. Do not use fictional demo information as real emergency information.
