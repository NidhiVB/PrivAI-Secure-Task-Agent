# PrivAI — GitHub Submission & Upload Guide

This guide provides instructions for uploading the **PrivAI — Secure Task Agent** source package to GitHub and sharing the repository link with hackathon evaluators.

---

## 1. Create a New GitHub Repository

1. Log into your GitHub account at [https://github.com](https://github.com).
2. In the top right corner, click the **`+`** icon and select **New repository**.
3. Configure repository settings:
   - **Repository name**: `PrivAI-Secure-Task-Agent` (or `PrivAI`)
   - **Description**: 
     > *PrivAI — Context-aware egress AI privacy firewall, bounded Secure Task Agent, employee privacy demo, policy engine, redaction, and cryptographic audit logging.*
   - **Visibility**: Select **Private** initially while verifying the upload, or **Public** if your security review is already complete.
   - **Initialize repository with**: **Leave unchecked** (do not add a README, .gitignore, or license, as these are already included in the package).
4. Click **Create repository**.

---

## 2. Upload the Package to GitHub

You can upload either via the Git CLI (recommended) or via GitHub's web interface.

### Option A: Using Git CLI (Recommended)

Open **Windows PowerShell** in the extracted directory:
```powershell
cd PrivAI_GitHub_Submission
# (Or navigate to the extracted submission folder)

# 1. Initialize local Git repository
git init

# 2. Add all sanitized files
git add .

# 3. Verify staged files before committing
git status

# 4. Commit files
git commit -m "Initial release: PrivAI Secure Task Agent & AI Privacy Firewall"

# 5. Set default branch to main
git branch -M main

# 6. Link to your GitHub repository (replace with your actual GitHub URL)
git remote add origin https://github.com/<your-username>/PrivAI-Secure-Task-Agent.git

# 7. Push to GitHub
git push -u origin main
```

---

### Option B: Using GitHub Web Uploader

1. On your newly created empty repository page, click the link: **"uploading an existing file"**.
2. Drag and drop all files and folders from `PrivAI_GitHub_Submission` into the browser window.
3. In the commit message box, enter:
   `Initial release: PrivAI Secure Task Agent & AI Privacy Firewall`
4. Click **Commit changes**.

---

## 3. Verify No Secrets or Databases Are Committed

Before sharing the repository with evaluators, perform a quick verification on GitHub:

1. **Check for `.env`**: Confirm that `.env` is **NOT** present in the repository file list. Only `.env.example` should be visible.
2. **Check for `.db` files**: In the GitHub search bar for your repo, search for `extension:db`. Verify that **0 results** are found.
3. **Check for `node_modules` and `.venv`**: Verify that neither directory was committed.
4. **Secret Scan**: Verify that no Groq API keys (`gsk_`) or sensitive credentials appear anywhere in commits or files.

---

## 4. Set Repository Visibility & Share with Evaluators

1. Once the upload and secret checks are verified:
   - Go to your repository's **Settings** tab.
   - Scroll down to the **Danger Zone**.
   - Click **Change visibility** $\to$ **Change to public**.
2. Confirm the change.
3. Copy your repository URL from the browser address bar:
   `https://github.com/<your-username>/PrivAI-Secure-Task-Agent`
4. Submit this URL to hackathon evaluators.

---

## 5. Summary of What Evaluators Can Run

Evaluators who clone your repository will be able to:
1. Copy `.env.example` to `.env`.
2. Run backend regression tests: `python -m pytest` (All 204 tests pass cleanly).
3. Run frontend tests: `cmd /c "npm test"` (All 36 tests pass cleanly).
4. Build production bundle: `cmd /c "npm run build"`.
5. Run automated demo verification: `python scripts/verify_employee_demo.py`.
6. Start both frontend and backend and interactively test `ALLOW`, `REDACT`, `BLOCK`, `REVIEW`, the Secure Task Agent, and the Employee Privacy Demo using safe synthetic data and the offline mock provider.
