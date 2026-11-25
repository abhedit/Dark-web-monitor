# ABHEDIT Exposure Monitor
A single-host, multi-tenant service for customer exposure monitoring. ABHEDIT operators provision workspaces and accounts. Customers register domains, prove ownership with a DNS TXT record, triage exposure cases, review activity and export JSON reports. Supports externally supplied dark-web intelligence and optional scheduled Have I Been Pwned domain checks. Source coverage depends on your contracted providers. No commercial data subscription is bundled.

## Run locally
Use Node.js 24. No npm dependencies required. In a Bash terminal:
```bash
npm test
npm run admin -- workspace 'Example Customer'
read -rsp 'New admin password: ' pass; echo
printf '%s' "$pass" | npm run admin -- member 'Example Customer' analyst@example.com admin
unset pass
npm start
```
Open http://localhost:8080 and sign in. In a second terminal run `npm run worker`. Passwords require at least 12 characters. Create additional members with role admin, analyst or viewer. The operator can use `reset NAME LOGIN` with a new password on stdin or `disable NAME LOGIN` to revoke access and sessions. Usernames are installation-wide unique. Run operator commands only on the trusted host.

## Connect a customer
1. As workspace administrator, add the customer's exact domain under Domains. Publish the displayed TXT value at the indicated hostname and click Check DNS. Keep the TXT record published. Verification expires after 24 hours and the worker refreshes proof every 12 hours. A missing or mismatched TXT record revokes verification when detected. Restore the record and click Check DNS to resume scanning. During a DNS outage the worker skips that domain and keeps the previous verification until its normal expiry.
2. For a licensed provider or ABHEDIT-owned integration, run `node admin.js feed-key 'Example Customer'` to issue or rotate that customer's push token. Configure the provider adapter to POST metadata over HTTPS to /api/feed. The token identifies the workspace. Use a stable source-prefixed event id. Send only aggregate counts and a short exposure title.
3. Example JSON body:
```json
{"domain":"example.com","id":"vendor:incident-348","title":"Employee emails in published breach","severity":"High","count":4}
```
Use the Authorization header with Bearer followed by the token. Allowed severities are High, Medium and Low. Replayed IDs update counts without reopening resolved cases. 401 indicates an invalid token, 403 indicates a domain lacks current proof. Retry after correcting the cause.
4. Optional breach provider: set HIBP_KEY for the worker and independently verify customer domains with HIBP. Confirm that your subscription permits managed-service use and covers each domain. The worker stores aggregate counts per breach, discards aliases, records provider errors and retains historical findings. A zero-result scan leaves earlier cases in the queue for human review. Provider documentation: https://haveibeenpwned.com/API/v3
5. Optional outbound notifications: set ALERT_ENDPOINTS to a JSON object mapping exact workspace names to operator-controlled HTTPS receiver URLs. The worker delivers new findings, retrying with backoff. Receivers should deduplicate by Idempotency-Key. Pending alerts are delivered when a receiver is first configured. Keep receiver URLs private.

## Host the application
Run `docker compose up -d --build`. Execute operator commands via `docker compose exec -T web node admin.js ...`. Configure PUBLIC_ORIGIN to the external HTTPS origin and route your TLS reverse proxy to 127.0.0.1:8080. Sign-in and browser writes check this exact origin. The HTTPS origin enables Secure cookies. Apply login throttling per client at the proxy; the built-in limit uses the socket peer. Run one web service and one worker with the same local volume. Encrypt the host volume, restrict host access and back up SQLite using the online backup API or stop both services before copying the volume. Restore the whole volume on an isolated host and test access before switching traffic. GET /health checks web/database readiness; monitor the worker separately.

## Commercial scope
Supports operator-managed onboarding and external invoicing. Self-service billing, SSO, MFA, multi-host failover, historical data retention policies and direct marketplace collection are outside this release. Review provider resale rights, retention terms, security and recovery in your deployment before onboarding paying customers. Tests use synthetic records and simulated DNS; live provider, DNS, TLS and notification delivery require your infrastructure.

## Threat intelligence and investigations
Each case shows the feed, channel, exposure category, severity, affected count, first receipt and latest ingestion. Search these fields in Findings. Active high-severity cases appear first. Open Investigation for the response guide and a persistent workspace-only analyst discussion. Viewers can read notes. The report includes classification and ingestion timestamps. Source coverage lists recorded provider checks and feed receipts by domain. Coverage records the most recent outcome for each source and domain, including failed scans and scans deferred after rate limiting. A completed scan can have zero matches. Use Refresh workspace to load activity received since you opened the dashboard.

Licensed feed adapters may add these optional fields to the existing payload:
```json
{"category":"Secret exposure","channel":"Paste site"}
```
Supported categories are Unclassified exposure, Identity exposure, Session exposure, Secret exposure, Infostealer exposure, Brand mention and Ransomware claim. Supported channels are Unspecified, Breach database, Forum, Messaging channel, Leak site, Paste site and Marketplace. Providers supply these labels and their own source coverage. Send descriptive metadata and aggregate counts. Exclude raw credentials, session cookies, tokens and leaked records.

For optional automated ransomware-claim monitoring, configure RANSOMWARE_LIVE_KEY on the worker for the Ransomware.live Pro API. Each DNS-verified domain is sent as a search term. The adapter accepts exact website/domain hostname matches, ignores uncorroborated name matches and stores provider-reported claims as cases for human review. Commercial operation requires provider authorization covering the intended customer service. Check the Source coverage view after enabling a provider. A successful scan can contain zero matching cases. Existing databases gain new tables at startup, and earlier findings retain their case IDs, status and first-seen timestamps.

## Customer plans and sales demonstration
Set a contracted domain allowance with `node admin.js plan 'Example Customer' 'Annual pilot' 5`. Customers see usage on the Domains tab. Existing workspaces without a plan keep their original allowance. Lowering a limit preserves existing assets and blocks further additions until capacity is available. Billing remains operator managed.

For a local sales walkthrough, run `node demo.js`, then `DATA_DIR=demo-data npm start` and sign in with the generated demo credentials. Use an unused local port if needed and set PUBLIC_ORIGIN to match. This creates a separate disposable database with three clearly attributed synthetic cases on a reserved example domain. The demo leaves domain verification disabled.
