# Google Workspace & GCP Service Account Setup Guide

This guide explains how to connect a cloned instance of `tenable-email` (the `assay` repository) to your organization's Google Workspace and Google Cloud Platform (GCP) environment.

---

## 1. Zero Code Changes Required

**You do not need to modify any Python source code.**

The Google intake integration (`google-alerts` source in `src/tenable_email/google_intake.py`) is completely configuration-driven:
- All API endpoints, query filters, scopes, timeouts, limits, and credential paths are passed through a configuration file (`google-intake.json`) or CLI options.
- The repository tracks a credential-free template: `google-intake.example.json`.
- The real runtime configuration `google-intake.json` is gitignored so organizational credentials and paths are never committed.

---

## 2. Architecture: How the Integration Works

Triage of user-reported phishing from Google Workspace requires two separate Google APIs working together:

1. **Google Workspace Alert Center API (`alertcenter.googleapis.com`)**:
   - Queries the alert feed for `type="User reported phishing"` and `source="Gmail phishing"`.
   - Each alert returns metadata and one or more `GmailMessageInfo` records containing the reported recipient email, subject, snippet, and an RFC 822 `Message-ID`.
   - Requires Domain-Wide Delegation impersonating an administrator account authorized to read Alert Center.

2. **Gmail REST API (`gmail.googleapis.com`)**:
   - The engine resolves the alert's RFC 822 `Message-ID` to an internal Gmail message ID using `users.messages.list(q='rfc822msgid:"..."')`.
   - It fetches the raw RFC 822 MIME bytes via `users.messages.get(format="raw")`.
   - **Per-recipient delegation**: Google requires domain-wide delegation to impersonate the specific mailbox owner holding the message. The engine handles this automatically: using your service account key, it mints a scoped, short-lived token impersonating each reported message's recipient on the fly and caches it for subsequent messages from that mailbox.

---

## 3. Step-by-Step Setup

### Step 1: Install Dependencies

The core package has zero mandatory dependencies. Minting tokens from a GCP service account JSON key requires the optional `google-auth` library:

```bash
# From the repository root:
pip install -e .[google]

# Or install directly:
pip install "google-auth>=2.35"
```

---

### Step 2: Configure Google Cloud Platform (GCP)

1. **Select or Create a GCP Project**:
   - Go to the [Google Cloud Console](https://console.cloud.google.com/).
   - Select an existing project (e.g. your security automation project) or create a new one.

2. **Enable Required APIs**:
   - Navigate to **APIs & Services** > **Library**.
   - Search for and **ENABLE** both of the following APIs:
     * **Google Workspace Alert Center API** (`alertcenter.googleapis.com`)
     * **Gmail API** (`gmail.googleapis.com`)
   *(Note: If either API is not enabled in this GCP project, API calls will fail with `HTTP 403 Forbidden: API not enabled`).*

3. **Create a Service Account**:
   - Navigate to **IAM & Admin** > **Service Accounts**.
   - Click **Create Service Account**.
   - Name: `workspace-alerts-triage` (or your preferred identifier).
   - Description: Service account for automated phishing triage.
   - Click **Create and Continue**.
   - *GCP IAM Roles*: Leave empty. No project-level IAM roles are needed because access to Workspace data is granted via Domain-Wide Delegation in Workspace Admin, not GCP roles.
   - Click **Done**.

4. **Generate a Service Account Key**:
   - Click on the newly created service account.
   - Go to the **Keys** tab > **Add Key** > **Create new key**.
   - Key type: **JSON**.
   - Click **Create**. A JSON key file will download to your workstation.
   - Store this key securely (for example at `~/.config/tenable-email/gcp-sa.json` or `/etc/tenable-email/service-account.json`). Ensure file permissions are restrictive (`chmod 600`).

5. **Copy the Service Account's Client ID**:
   - On the service account's **Details** tab, find the **OAuth 2 Client ID** (a 21-digit number).
   - Copy this number; you will need it in Step 3.

---

### Step 3: Configure Google Workspace Admin (Domain-Wide Delegation)

1. Sign in to the [Google Workspace Admin Console](https://admin.google.com/) as a **Super Administrator**.
2. In the navigation menu, go to **Security** > **Access and data control** > **API controls**.
3. Scroll down to the **Domain-wide delegation** section and click **Manage Domain Wide Delegation**.
4. Click **Add new**:
   - **Client ID**: Paste the 21-digit numeric Client ID of your GCP service account.
   - **OAuth Scopes (comma-delimited)**:
     ```
     https://www.googleapis.com/auth/apps.alerts, https://www.googleapis.com/auth/gmail.readonly
     ```
   - Click **Authorize**.

---

### Step 4: Configure Local Application (`google-intake.json`)

1. Copy the example configuration template:
   ```bash
   cp google-intake.example.json google-intake.json
   ```

2. Edit `google-intake.json`:
   ```json
   {
     "service_account_file": "/path/to/your/gcp-service-account.json",
     "subject": "secops-admin@yourdomain.com",
     "limit": 10,
     "token": "",
     "token_file": "",
     "alert_center_token": "",
     "gmail_token": "",
     "scopes": [
       "https://www.googleapis.com/auth/apps.alerts",
       "https://www.googleapis.com/auth/gmail.readonly"
     ],
     "alert_center_base_url": "https://alertcenter.googleapis.com/v1beta1",
     "gmail_base_url": "https://gmail.googleapis.com/gmail/v1",
     "alert_type": "User reported phishing",
     "alert_source": "Gmail phishing",
     "order_by": "create_time desc",
     "timeout_seconds": 30
   }
   ```

### Configuration Fields Explained

| Field | Purpose |
|---|---|
| `service_account_file` | Absolute or relative path to the GCP service account JSON key file. |
| `subject` | Email address of an admin user in your Google Workspace domain authorized to read Alert Center alerts. |
| `limit` | Max number of reported messages to process per run (e.g. `10` or `20`). Set to `null` for unlimited (pages up to 5,000 alerts). |
| `scopes` | OAuth 2.0 scopes requested during token minting. Defaults to `apps.alerts` and `gmail.readonly`. |
| `alert_type` | Alert Center query filter type. Default: `"User reported phishing"`. |
| `alert_source` | Alert Center query filter source. Default: `"Gmail phishing"`. |
| `order_by` | Ordering of alerts from Alert Center. Default: `"create_time desc"`. |
| `timeout_seconds` | HTTP connection and read timeout. Default: `30`. |
| `token` / `token_file` | Leave empty when using `service_account_file`. Only used if supplying static pre-minted Bearer tokens. |

---

## 4. Execution & Verification

### Test Run via CLI

Run the triage engine against your live Google feed in dry-run mode (outputting ledger and case receipts locally without modifying mailboxes):

```bash
# Run triage on the latest 5 reported messages:
python3 -m tenable_email run \
  --source google-alerts \
  --config google-intake.json \
  --limit 5 \
  --provider ledger \
  --out /tmp/triage-test
```

### Inspect Results via the Web Dashboard

Launch the zero-JavaScript loopback HTTP server to review verdicts, evidence, and model agreement:

```bash
python3 -m tenable_email ledger serve /tmp/triage-test/ledger.sqlite3 --port 8765
```
Open `http://127.0.0.1:8765` in your browser.

### Using the Interactive Demo Wrapper

If using the repository's interactive menu:
```bash
./tools/demo.sh
# Select option 2 (google) to capture live alerts.
# Select option 5 (serve) to browse the results.
```

---

## 5. Troubleshooting & Common Pitfalls

| Symptom / Error | Cause | Solution |
|---|---|---|
| `SourceError: google_auth_missing` | `google-auth` is not installed in the Python environment. | Run `pip install -e .[google]` or `pip install google-auth`. |
| `HTTP 403: Alert Center API has not been used... or it is disabled` | `alertcenter.googleapis.com` is disabled in the GCP project. | Enable Google Workspace Alert Center API in the GCP Console under APIs & Services. |
| `HTTP 403: Gmail API has not been used... or it is disabled` | `gmail.googleapis.com` is disabled in the GCP project. | Enable Gmail API in the GCP Console under APIs & Services. |
| `HTTP 403: Client is unauthorized to retrieve access tokens using this method` | Domain-Wide Delegation is missing or incorrect. | Ensure the 21-digit Client ID is authorized under Domain-Wide Delegation in Google Workspace Admin with both required scopes. |
| `HTTP 403: Delegation denied for <admin>` | Gmail API call attempted using the Alert Center admin subject instead of recipient delegation. | Ensure `gmail_token` is empty in `google-intake.json` so the engine uses automatic per-recipient delegation. |
| Alert fetched, but message not found / skipped | The user permanently deleted the reported email or it was quarantined before triage ran. | Expected behavior. The engine records an explicit `UNRETRIEVABLE` unknown finding in the evidence chain and does not crash. |
