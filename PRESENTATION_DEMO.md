# LifeVault Presentation Demo

**Target duration: 6 minutes** (within the requested 5–7 minute range). Use a demo account and load demo data before presenting. Demo details are fictional.

| Time | Step | Demo flow and talking points |
|---|---|---|
| 0:00–0:35 | 1. Login | Sign in to the local demo account. Point out that passwords are hashed and that the recovery code is local, shown once, and not emailed. |
| 0:35–1:05 | 2. Dashboard | Show document totals, active/expiring/expired counts, emergency contacts, alerts, and the dashboard shortcut to Emergency Mode. |
| 1:05–1:35 | 3. Readiness Score | Open Readiness. Explain its five equal checks and state the disclaimer: it is a project-defined completeness indicator, not a safety or medical certification. |
| 1:35–2:30 | 4. Add/view documents | Open Document Vault, show search and filters, add a record, optionally attach a file and mark it for Emergency Pack, then open a demo attachment to show local decryption. |
| 2:30–3:00 | 5. Expiry tracking | Show the Vehicle Insurance demo item marked Expiring Soon, explain the 30-day rule, then use the category/status filters. |
| 3:00–3:35 | 6. Emergency contacts | Show two fictional contacts, edit one if time permits, and demonstrate that the call action opens the system phone handler when configured. |
| 3:35–4:15 | 7. Emergency Pack | Show selected critical documents, contacts, and profile information included in the pack. |
| 4:15–4:50 | 8. Emergency Mode | Open Emergency Mode and point out the name, blood group, allergies, vehicle, insurance, instructions, contact call buttons, and critical documents. |
| 4:50–5:35 | 9. Security explanation | Explain SQLite persistence, PBKDF2 password hashing, Fernet-encrypted attachments, password/recovery-wrapped vault key, 15-minute inactivity lock, and the local prototype limitations. Mention Google OAuth is optional and requires the user's own Desktop credentials. |
| 5:35–6:00 | 10. Conclusion | Recap the goal: organise documents, monitor expiry, and make emergency details quickly accessible in one local desktop application. |

## Common Viva Questions

**1. What problem does LifeVault address?**  
Important records and emergency information are often scattered; LifeVault organises them locally and makes selected details faster to find.

**2. Which technologies are used?**  
Python, CustomTkinter, SQLite, PBKDF2-HMAC-SHA256 from the Python standard library, Fernet from `cryptography`, and optional Google OAuth via `google-auth-oauthlib`.

**3. Are passwords stored in the database?**  
No. A salted PBKDF2-HMAC-SHA256 hash and salt are stored. The password-derived key unwraps the random vault key; it is not stored as plaintext.

**4. How are document files protected?**  
Attachments are encrypted with Fernet before being written to the user's local vault directory. Opening one decrypts it to a temporary file for the operating-system handler.

**5. How does password recovery work without email?**  
The user enters the locally issued recovery code. It unlocks the vault key so the app can set a new master password and rewrap that same key. The recovery code is then rotated.

**6. What happens if both the password and recovery code are lost?**  
The encrypted vault cannot be recovered. There is no hidden email reset or backdoor.

**7. How is an expiry status calculated?**  
Past dates are Expired; dates from today through 30 days ahead are Expiring Soon; later dates and records without an expiry are Active.

**8. What does the readiness percentage mean?**  
It awards 20 points each for an emergency contact, insurance information, vehicle information, any document, and at least one valid document. It is not official certification.

**9. What data is included in Emergency Mode?**  
The saved emergency profile, contacts flagged for emergencies, and documents marked as critical for the Emergency Pack.

**10. Why is SQLite used?**  
It is available in Python's standard library, persists data locally, and is suitable for a small single-user desktop prototype.

**11. Does Google sign-in unlock the encrypted vault by itself?**  
No. OAuth verifies the Google identity, but the local master password is still required to unlock the locally encrypted vault.

**12. Is this production-ready?**  
No. It is a college/local prototype. It does not provide cloud backup, independent security certification, emergency dispatch, or protection from a compromised host computer.
