# Sam’s Vault: a free, private password app

Sam’s Vault is a web app that installs on his iPhone's Home Screen and works like a normal app.
It's **free to host**, needs **no Apple developer account**, and works **offline**.

**Who can see his passwords:** only someone who knows his master password (or has his paper
emergency code). Everything is encrypted *inside his phone* before it's saved. The website
only delivers the app's code. It never receives, stores or sees any passwords.

---

## 1. Put it online for free (GitHub Pages, about 10 minutes)

1. Create a free account at **github.com**.
2. Click **+** (top right) → **New repository**. Name it `vault`, choose **Public**, click **Create repository**.
3. On the new page, click **uploading an existing file**. Drag in **all 9 files** from this folder
   (`index.html`, `app.js`, `styles.css`, `sw.js`, `manifest.webmanifest` and the 3 `.png` icons and `logo.svg`).
   Click **Commit changes**.
4. Go to **Settings → Pages**. Under *Branch*, pick **main** and **/ (root)**, then click **Save**.
5. Wait a minute and refresh. Your app's address appears at the top, for example:
   **`https://yourname.github.io/vault/`**

> The code is public, which is fine. It contains no passwords or secrets, and anyone can check
> what it does. His encrypted data never goes to GitHub.

*Alternative:* Cloudflare Pages or Netlify (free) also work. Upload the same folder.

---

## 2. Install it on his iPhone

1. On his iPhone, open the address in **Safari**.
2. Tap **Share** (square with an arrow) → **Add to Home Screen** → **Add**.
3. Open **Sam’s Vault from the Home Screen** (not from Safari) and set it up there.

⚠️ Always use the Home Screen icon. On iPhone, the Home Screen app keeps its own storage,
separate from Safari tabs, and is protected from Safari's automatic clean-up.

---

## 3. The handover: making sure only he has access

1. Give him the phone on the **Welcome** screen. He creates the master password **alone**. Don't watch.
2. He writes down the **emergency code** on paper and keeps it safe. No photos.
3. Face ID: turn it on only if **his face is the only one** set up on his iPhone.
4. Have him tap **Settings → Save an encrypted backup** → **Save to Files** (iCloud Drive) after
   adding his passwords, and again now and then. The app reminds him monthly.

After this, you can't get in. The app has no back door and no reset.

---

## Features

**Easy for him:** large text and buttons • Face ID unlock • search • color-coded types (Banking,
Email, Shopping…) • Favorites • one-tap copy from the list • "Create a strong password for me" •
**Security Check** score out of 100 that flags weak, reused and old passwords • light and dark mode

**Security:**

| Protection | How |
|---|---|
| Encryption | AES-256-GCM via the browser's built-in Web Crypto |
| Master password | Never stored. Stretched with PBKDF2-SHA256, 600,000 rounds |
| Emergency code | 24 random characters (120 bits), the only way in if he forgets his password |
| No data leaves the phone | Content Security Policy `connect-src 'none'` blocks every network request |
| Face ID | Passkey with the WebAuthn PRF extension (iOS 18+). If his phone doesn't support it, the app says so and he uses his password |
| Guessing | After 5 wrong tries: 30 s → 1 min → 5 min → 15 min → 1 hour waits |
| Privacy | Hides contents in the app switcher. Locks when he leaves (configurable) and after 5 min idle |
| Backups | Exported file stays encrypted. Restore on a new phone with his master password |
| Safe display | All text is escaped, so a malicious entry can't run code |

---

## Things to know

- **Back up.** His passwords live on his phone. If the phone is lost and there's no backup file,
  they're gone. The backup is useless to anyone without his master password or code.
- **Lost phone:** install Sam’s Vault on the new phone → **Restore from a backup file** → unlock with his master password.
- **Forgot password:** tap **Forgot your password?** and enter the emergency code.
- **Forgot both:** can't be recovered, by design.
- **Copying:** iPhone web apps can't fully control the clipboard. A copied password stays there until
  something else is copied (the app tries to clear it after 1 minute while open).
- **Trust:** whoever controls the GitHub account can change the app's code. Once it's set up,
  don't change the files unless he knows about it. For extra peace of mind, create the GitHub
  account in **his** name.

## Updating the app later

Edit the files, change `VERSION` in `sw.js` (e.g. `sams-vault-v3`), and upload again. His phone picks up
the new version the next time it opens Vault with internet. His data isn't touched.
