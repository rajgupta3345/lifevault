# LifeVault Project Documentation

## 1. Project Title
**LIFEVault — Smart Personal Document & Emergency Management System**

## 2. Introduction
LifeVault is a desktop application that keeps personal document records and essential emergency details organised in one local vault. It combines encrypted file storage, expiry monitoring, emergency contacts, and a quick emergency information screen.

## 3. Problem Statement
Important identity, insurance, vehicle, education, financial, and medical records are often scattered across files and devices. During an urgent situation, people may not be able to find current documents, contact details, or essential profile information quickly.

## 4. Proposed Solution
Provide a local-first desktop vault with authenticated access, encrypted document attachments, expiry status, editable emergency information, a selected Emergency Pack, and an at-a-glance readiness indicator.

## 5. Objectives
- Organise document metadata and optional attachments.
- Track active, expiring-soon, and expired records.
- Store emergency contacts and profile details for quick access.
- Protect local accounts with password hashing and attachment encryption.
- Provide clear, demonstrable workflows using fictional demo data.

## 6. Core Features
- Account registration and sign-in with PBKDF2-HMAC-SHA256 salted password hashes.
- Master-password and recovery-code wrapped vault key, with local recovery and key rotation.
- Optional Google Desktop OAuth for identity verification, without replacing the local vault password.
- Per-user SQLite records, encrypted file attachments, document search and filters, expiry status, contacts, profile, audit activity, settings, and 15-minute inactivity lock.

## 7. Emergency Mode
Emergency Mode prioritises the user's name, blood group, allergies, vehicle and insurance information, emergency instructions, emergency contacts with call actions, and documents marked for the Emergency Pack. It is a fast local display, not an emergency dispatch service.

## 8. Readiness Score
The project-defined score has five equally weighted checks (20 points each): an emergency contact exists, insurance information exists, vehicle information exists, at least one document exists, and at least one document is valid/non-expired. It is an organisational completeness indicator, not an official safety or medical certification.

## 9. Expiry Tracker
A document is **EXPIRED** when its date is before today, **EXPIRING SOON** when it expires within the next 30 days, and **ACTIVE** otherwise. A missing expiry date is active. Invalid dates are rejected when records are added.

## 10. System Architecture
- **Presentation:** CustomTkinter desktop interface and dialogs.
- **Application logic:** `main.py`, handling authentication, validation, encryption, workflows, and status calculations.
- **Persistence:** SQLite database (`lifevault.db`) with per-user ownership and foreign-key cascades.
- **File storage:** Attachments encrypted with Fernet and stored under the local `vault/` folder. Files are decrypted to a temporary directory only when opened.
- **Optional identity provider:** Google OAuth Desktop flow using a user-supplied `credentials.json`.

## 11. Data Flow
1. The user registers or signs in; passwords are salted and hashed before storage.
2. A random vault key is wrapped using a key derived from the master password. A separate recovery-code-derived key provides recovery access.
3. Document metadata is written to SQLite; an attached file is encrypted before it is written to the user's vault directory.
4. Search, status, readiness, dashboard, and emergency views use the signed-in user's SQLite rows.
5. Opening an attachment decrypts it to a temporary file and launches the system file handler. Temporary files are cleaned up at app shutdown.

## 12. Database Design
- **users:** Name, unique email, password hash/salt, password-wrapped vault key, recovery hash/salt, and recovery-wrapped vault key.
- **documents:** Owner, name, category, encrypted path, original filename, optional expiry, Emergency Pack flag, and creation time.
- **contacts:** Owner, name, phone, relationship, emergency flag, and creation time.
- **profile:** Owner, full name, blood group, allergies/medical notes, vehicle number, insurance information, and emergency instructions.
- **audit_log:** Owner, action, details, and timestamp.

SQLite initialization creates missing tables and safely adds newly introduced columns to an existing database.

## 13. Security Approach
- Passwords and recovery codes are stored as salted PBKDF2-HMAC-SHA256 hashes; plaintext credentials are not stored.
- The random Fernet vault key is encrypted under separate password-derived and recovery-code-derived keys. Password reset rewraps the same vault key, preserving encrypted attachments.
- Document attachments are encrypted at rest. Database metadata and temporary opened files are not encrypted by this prototype; temporary files are removed at normal shutdown.
- SQL calls use parameters, document/contact queries are scoped to the current user, and foreign keys cascade on account deletion.
- Google OAuth requests OpenID and basic email/profile identity scopes only. No client secret is embedded; the owner supplies `credentials.json`.
- This is a college/local prototype, not a production security product. Local device access, backups, key management, temporary files, and the host operating system remain relevant risks.

## 14. Technology Stack
Python 3.11+, CustomTkinter, SQLite (standard library), `cryptography` Fernet, and `google-auth-oauthlib` for optional Google OAuth. Pillow is listed as a UI dependency.

## 15. Installation
From the project directory, install Python 3.11 or newer, then run:

```powershell
python -m pip install -r requirements.txt
```

On Windows, `Run_LifeVault.bat` performs the dependency install and starts the application.

## 16. How to Run

```powershell
python main.py
```

Optional Google setup is documented in `Google_Login_Setup.txt`. Without `credentials.json`, Google sign-in displays the setup instructions and the normal local sign-in remains available.

## 17. How to Use
1. Create an account and securely save the displayed recovery code.
2. Sign in with the master password.
3. Add records and optional files in Document Vault; set expiry and Emergency Pack flags as appropriate.
4. Add emergency contacts and complete the profile in Settings.
5. Review readiness, expiry notices, and recent activity.
6. Use Emergency Pack and Emergency Mode for quick access.

## 18. Demo Data
Settings → Load Demo Data adds fictional profile information, two sample contacts, and four sample document attachments: Driving Licence, Vehicle Insurance, Passport, and Vehicle Certificate. The insurance sample expires soon to demonstrate tracking. Files are encrypted locally; demo entries are idempotent by their sample names. Do not use this fictional data for real emergencies.

## 19. Limitations
- Desktop/local use only; no cloud sync, remote backup, email password reset, or emergency dispatch.
- Google OAuth verifies identity, but a local master password is still required to unlock the vault.
- Only document attachments are encrypted. SQLite metadata and opened temporary copies are local plaintext.
- Phone actions depend on a configured operating-system handler.
- Recovery is possible only while the recovery code remains available.
- This prototype has not undergone an independent security or usability audit.

## 20. Future Scope
Potential future work includes encrypted backup/restore, OS keychain integration, safer temporary-file handling, configurable inactivity locking, expanded automated GUI tests, and an independent security review. These should be considered only with a defined threat model and privacy review.

## 21. Conclusion
LifeVault demonstrates a practical local desktop workflow for organising important documents and showing emergency information quickly. It combines password-based access, encrypted attachments, expiry tracking, contacts, profile data, Emergency Pack, and a transparent project-defined readiness score while clearly documenting prototype limitations.
