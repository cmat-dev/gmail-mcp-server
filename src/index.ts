import express, { Request, Response, NextFunction } from "express";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { google } from "googleapis";
import { z } from "zod";
import { GmailService } from "./gmail-service.js";
import { TokenStore } from "./token-store.js";
import { AdminAuth, AdminSession } from "./admin-auth.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.PORT || "3000", 10);
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD!;
const SESSION_SECRET = process.env.SESSION_SECRET || process.env.ENCRYPTION_KEY!;
const SECURE_SERVER = SERVER_URL.startsWith("https://");
const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/userinfo.email",
];

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

const tokenStore = new TokenStore();
const adminAuth = new AdminAuth({
  adminPassword: ADMIN_PASSWORD,
  sessionSecret: SESSION_SECRET,
  secureCookie: SECURE_SERVER,
});

if (process.env.NODE_ENV === "production" && !SECURE_SERVER) {
  throw new Error("SERVER_URL must use HTTPS in production");
}

function formatAccountError(err: any): string {
  const raw =
    err?.response?.data?.error_description ??
    err?.response?.data?.error ??
    err?.message ??
    String(err);

  if (/invalid_grant/i.test(String(raw))) {
    return "OAuth authorization is invalid or revoked. Re-authorize this account via /setup.";
  }

  return String(raw);
}

// ---------------------------------------------------------------------------
// Gmail service factory — exchanges stored refresh token for access token
// ---------------------------------------------------------------------------

function makeOAuth2Client() {
  return new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    `${SERVER_URL}/oauth/callback`
  );
}

async function getGmailServiceForAccount(email: string): Promise<GmailService> {
  const refreshToken = tokenStore.getRefreshToken(email);
  if (!refreshToken) {
    throw new Error(
      `Account "${email}" is not connected. Use list_accounts to see connected accounts, or add it via the /setup page.`
    );
  }

  const oauth2 = makeOAuth2Client();
  oauth2.setCredentials({ refresh_token: refreshToken });

  const { token } = await oauth2.getAccessToken();
  if (!token) {
    throw new Error(
      `Failed to get access token for "${email}". The account may need to be re-authorized via /setup.`
    );
  }

  return new GmailService(token);
}

function resolveAccounts(account: string): string[] {
  if (account.toLowerCase() === "all") {
    const all = tokenStore.listAccounts().map((a) => a.email);
    if (all.length === 0) {
      throw new Error("No accounts connected. Add accounts via the /setup page.");
    }
    return all;
  }
  if (!tokenStore.hasAccount(account)) {
    const available = tokenStore.listAccounts().map((a) => a.email);
    throw new Error(
      `Account "${account}" is not connected. Available accounts: ${available.join(", ") || "none"}`
    );
  }
  return [account];
}

// ---------------------------------------------------------------------------
// MCP server factory — registers all tools
// ---------------------------------------------------------------------------

function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "gmail-mcp-server",
    version: "1.0.0",
  });

  // ---- list_accounts ----
  server.tool(
    "list_accounts",
    "List all connected Gmail accounts. Use the email addresses returned here as the 'account' parameter in other tools.",
    {},
    async () => {
      const accounts = tokenStore.listAccounts();
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                connected_accounts: accounts,
                usage_hint:
                  "Use any email address as the 'account' parameter, or use 'all' to query every account.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // ---- list_emails ----
  server.tool(
    "list_emails",
    "Search and list emails. Supports Gmail search syntax (is:unread, from:, newer_than:7d, etc). Use account='all' to search across all connected accounts.",
    {
      account: z
        .string()
        .describe(
          "Email address of the account to search, or 'all' for every connected account"
        ),
      query: z
        .string()
        .optional()
        .describe(
          "Gmail search query (e.g. 'is:unread', 'from:user@example.com newer_than:2d', 'subject:invoice')"
        ),
      max_results: z
        .number()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of emails to return per account (1-100)"),
    },
    async ({ account, query, max_results }) => {
      const accounts = resolveAccounts(account);
      const allResults: Array<{
        account: string;
        emails: any[];
        error?: string;
      }> = [];

      for (const email of accounts) {
        try {
          const gmail = await getGmailServiceForAccount(email);
          const emails = await gmail.listEmails(query, max_results);
          allResults.push({ account: email, emails });
        } catch (err: any) {
          allResults.push({
            account: email,
            emails: [],
            error: formatAccountError(err),
          });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(allResults, null, 2),
          },
        ],
      };
    }
  );

  // ---- get_email ----
  server.tool(
    "get_email",
    "Get the full content of a specific email including body, headers, and any unsubscribe links found.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const email = await gmail.getEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account, ...email }, null, 2),
          },
        ],
      };
    }
  );

  // ---- archive_email ----
  server.tool(
    "archive_email",
    "Archive an email by removing it from the inbox. The email remains accessible via search or All Mail.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID to archive"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.archiveEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account,
              ...result,
              message: `Email ${message_id} archived successfully.`,
            }),
          },
        ],
      };
    }
  );

  // ---- apply_label ----
  server.tool(
    "apply_label",
    "Apply a label to an email. Creates the label if it does not already exist.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID"),
      label_name: z
        .string()
        .describe(
          "Label name to apply (e.g. 'Receipts', 'Follow Up'). Created automatically if it does not exist."
        ),
    },
    async ({ account, message_id, label_name }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.applyLabel(message_id, label_name);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account,
              ...result,
              message: `Label "${label_name}" applied to email ${message_id}.`,
            }),
          },
        ],
      };
    }
  );

  // ---- unsubscribe_email ----
  server.tool(
    "unsubscribe_email",
    "Attempt to unsubscribe from a mailing list. Tries List-Unsubscribe header (HTTP and mailto), then scans the email body for unsubscribe links.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z
        .string()
        .describe("The Gmail message ID to unsubscribe from"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.unsubscribeEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account, ...result }, null, 2),
          },
        ],
      };
    }
  );

  // ---- batch_process ----
  server.tool(
    "batch_process",
    "Fetch a batch of emails matching a query for triage. Returns structured data so you can decide which actions to take on each email. Use account='all' to scan all accounts.",
    {
      account: z
        .string()
        .describe(
          "Email address of the account to search, or 'all' for every connected account"
        ),
      query: z
        .string()
        .describe(
          "Gmail search query (e.g. 'is:unread category:promotions', 'newer_than:7d')"
        ),
      max_results: z
        .number()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of emails to fetch per account"),
    },
    async ({ account, query, max_results }) => {
      const accounts = resolveAccounts(account);
      const allResults: Array<{
        account: string;
        emails: any[];
        error?: string;
      }> = [];

      for (const email of accounts) {
        try {
          const gmail = await getGmailServiceForAccount(email);
          const emails = await gmail.batchProcess(query, max_results);
          allResults.push({ account: email, emails });
        } catch (err: any) {
          allResults.push({
            account: email,
            emails: [],
            error: formatAccountError(err),
          });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                total: allResults.reduce((n, r) => n + r.emails.length, 0),
                query,
                results: allResults,
                hint: "Review each email and decide whether to archive, label, unsubscribe, or skip. Use the individual tools with the correct account parameter.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

export const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------------
// Admin authentication and setup-page security
// ---------------------------------------------------------------------------

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setupUrl(message?: string): string {
  return message ? `/setup?message=${encodeURIComponent(message)}` : "/setup";
}

function sendLoginPage(res: Response, status = 401, message?: string): void {
  res.status(status).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Gmail MCP - Admin Login</title>
      <style>
        body { font-family: system-ui, sans-serif; max-width: 400px; margin: 80px auto; padding: 0 20px; }
        h1 { font-size: 1.5rem; }
        input { padding: 10px; width: 100%; box-sizing: border-box; margin: 8px 0 12px; }
        button { padding: 10px 24px; background: #4285f4; color: white; border: 0; border-radius: 6px; cursor: pointer; }
        .msg { padding: 10px; background: #fce4ec; border-radius: 6px; margin-bottom: 12px; }
      </style>
    </head>
    <body>
      <h1>Gmail MCP Admin Login</h1>
      ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ""}
      <form method="POST" action="/setup/login" autocomplete="off">
        <label for="password">Admin password</label>
        <input id="password" type="password" name="password" autocomplete="current-password" required autofocus />
        <button type="submit">Login</button>
      </form>
    </body>
    </html>
  `);
}

app.use(["/setup", "/oauth"], (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  );
  if (SECURE_SERVER) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

// Strip legacy password-bearing links without reading or reusing the password.
app.use(["/setup", "/oauth"], (req, res, next) => {
  if (req.query.key !== undefined) {
    res.redirect(303, "/setup");
    return;
  }
  next();
});

function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const session = adminAuth.readSession(req.headers.cookie);
  if (!session) {
    if (req.method === "GET" && req.path === "/setup") {
      sendLoginPage(res);
    } else {
      res.status(401).send("Unauthorized");
    }
    return;
  }
  res.locals.adminSession = session;
  next();
}

function requireCsrf(req: Request, res: Response, next: NextFunction): void {
  const session = res.locals.adminSession as AdminSession | undefined;
  if (!session || !adminAuth.verifyCsrf(session, req.body.csrfToken)) {
    res.status(403).send("Invalid request token");
    return;
  }
  next();
}

app.post("/setup/login", (req: Request, res: Response) => {
  const clientId = req.ip || req.socket.remoteAddress || "unknown";
  if (adminAuth.isLoginBlocked(clientId)) {
    res.setHeader("Retry-After", "900");
    sendLoginPage(res, 429, "Too many failed attempts. Try again later.");
    return;
  }

  if (!adminAuth.verifyPassword(req.body.password)) {
    adminAuth.recordLoginFailure(clientId);
    sendLoginPage(res, 401, "Invalid password.");
    return;
  }

  adminAuth.clearLoginFailures(clientId);
  const { token } = adminAuth.createSession();
  res.cookie(adminAuth.cookieName, token, adminAuth.sessionCookieOptions);
  res.redirect(303, "/setup");
});

app.post("/setup/logout", requireAdmin, requireCsrf, (_req, res) => {
  const { maxAge: _maxAge, ...clearOptions } = adminAuth.sessionCookieOptions;
  res.clearCookie(adminAuth.cookieName, clearOptions);
  res.redirect(303, "/setup");
});

// ---------------------------------------------------------------------------
// Setup page — manage connected Gmail accounts
// ---------------------------------------------------------------------------

app.get("/setup", requireAdmin, (req: Request, res: Response) => {
  const accounts = tokenStore.listAccounts();
  const message = req.query.message as string | undefined;
  const session = res.locals.adminSession as AdminSession;
  const csrfToken = escapeHtml(session.csrfToken);

  const accountRows = accounts.length > 0
    ? accounts
        .map(
          (a) => `
        <tr>
          <td>${escapeHtml(a.email)}</td>
          <td>${escapeHtml(new Date(a.addedAt).toLocaleDateString())}</td>
          <td>
            <form method="POST" action="/setup/remove" style="display:inline">
              <input type="hidden" name="csrfToken" value="${csrfToken}" />
              <input type="hidden" name="email" value="${escapeHtml(a.email)}" />
              <button type="submit" style="color:red;background:none;border:1px solid red;padding:4px 12px;cursor:pointer">Remove</button>
            </form>
          </td>
        </tr>`
        )
        .join("")
    : `<tr><td colspan="3" style="text-align:center;color:#888">No accounts connected yet</td></tr>`;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Gmail MCP - Setup</title>
      <style>
        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; }
        h1 { font-size: 1.5rem; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eee; }
        th { font-weight: 600; border-bottom: 2px solid #ddd; }
        .btn { display: inline-block; padding: 10px 24px; background: #4285f4; color: white; text-decoration: none; border-radius: 6px; font-size: 14px; }
        .btn:hover { background: #3367d6; }
        .msg { padding: 12px; background: #e8f5e9; border-radius: 6px; margin-bottom: 16px; }
        .msg.error { background: #fce4ec; }
      </style>
    </head>
    <body>
      <h1>Gmail MCP Server - Setup</h1>
      ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ""}
      <table>
        <thead><tr><th>Account</th><th>Added</th><th></th></tr></thead>
        <tbody>${accountRows}</tbody>
      </table>
      <form method="POST" action="/oauth/start" style="display:inline">
        <input type="hidden" name="csrfToken" value="${csrfToken}" />
        <button class="btn" type="submit" style="border:0;cursor:pointer">+ Add Gmail Account</button>
      </form>
      <form method="POST" action="/setup/logout" style="display:inline;margin-left:8px">
        <input type="hidden" name="csrfToken" value="${csrfToken}" />
        <button type="submit" style="padding:10px 18px;background:white;border:1px solid #aaa;border-radius:6px;cursor:pointer">Log out</button>
      </form>
      ${accounts.length > 0 ? `
      <div style="margin-top:24px;padding:16px;background:#fff3cd;border-radius:6px">
        <strong>Important:</strong> After adding/removing accounts, copy the value below and paste it as the <code>TOKENS_DATA</code> environment variable in Railway. This ensures accounts survive redeploys.
        <div style="margin-top:8px">
          <textarea readonly style="width:100%;height:60px;font-family:monospace;font-size:11px;box-sizing:border-box">${escapeHtml(tokenStore.getTokensDataForExport())}</textarea>
        </div>
      </div>
      ` : ""}
      <hr style="margin-top:40px;border:none;border-top:1px solid #eee" />
      <p style="color:#888;font-size:13px">
        MCP endpoint: <code>${SERVER_URL}/mcp</code><br/>
        Connected accounts: ${accounts.length}
      </p>
    </body>
    </html>
  `);
});

app.post("/setup/remove", requireAdmin, requireCsrf, (req: Request, res: Response) => {
  const email = req.body.email;

  if (email && tokenStore.hasAccount(email)) {
    tokenStore.removeAccount(email);
    res.redirect(303, setupUrl(`Removed ${email}`));
  } else {
    res.redirect(303, setupUrl("Account not found"));
  }
});

// ---------------------------------------------------------------------------
// OAuth flow — server-managed Google auth
// ---------------------------------------------------------------------------

app.post("/oauth/start", requireAdmin, requireCsrf, (_req: Request, res: Response) => {
  const session = res.locals.adminSession as AdminSession;
  const state = adminAuth.createOAuthState(session);
  const oauth2 = makeOAuth2Client();
  const url = oauth2.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    state,
  });

  res.redirect(url);
});

app.get("/oauth/start", (_req: Request, res: Response) => {
  res.redirect(303, "/setup");
});

app.get("/oauth/callback", requireAdmin, async (req: Request, res: Response) => {
  const code = req.query.code as string;
  const state = req.query.state as string;
  const error = req.query.error as string;
  const session = res.locals.adminSession as AdminSession;

  if (!adminAuth.consumeOAuthState(state, session)) {
    res.status(400).send("Invalid or expired OAuth state. Return to /setup and try again.");
    return;
  }

  if (error) {
    res.redirect(303, setupUrl(`OAuth error: ${error}`));
    return;
  }

  if (!code) {
    res.redirect(303, setupUrl("No authorization code received"));
    return;
  }

  try {
    const oauth2 = makeOAuth2Client();
    const { tokens } = await oauth2.getToken(code);

    if (!tokens.refresh_token) {
      res.redirect(303, setupUrl("No refresh token received. Try removing the app from your Google account permissions and re-adding."));
      return;
    }

    // Get the user's email address
    oauth2.setCredentials(tokens);
    const oauth2Api = google.oauth2({ version: "v2", auth: oauth2 });
    const userInfo = await oauth2Api.userinfo.get();
    const email = userInfo.data.email;

    if (!email) {
      res.redirect(303, setupUrl("Could not determine email address"));
      return;
    }

    tokenStore.addAccount(email, tokens.refresh_token);

    res.redirect(303, setupUrl(`Successfully connected ${email}`));
  } catch {
    console.error("[oauth/callback] OAuth exchange failed");
    res.redirect(303, setupUrl("OAuth authorization failed. Please try again."));
  }
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    accounts: tokenStore.size,
  });
});

// ---------------------------------------------------------------------------
// MCP transport — Streamable HTTP (stateless: each request gets a fresh server)
// ---------------------------------------------------------------------------

app.post("/mcp", async (req: Request, res: Response) => {
  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless — no session tracking
    });

    const mcpServer = createMcpServer();
    await mcpServer.connect(transport);

    await transport.handleRequest(req, res, req.body);

    // Clean up after response is sent
    res.on("close", () => {
      mcpServer.close().catch(() => {});
      transport.close().catch(() => {});
    });
  } catch (err: any) {
    console.error("[mcp] Error handling request:", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: err.message },
        id: null,
      });
    }
  }
});

app.get("/mcp", async (req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "SSE streams not supported in stateless mode. Use POST." },
    id: null,
  });
});

app.delete("/mcp", async (req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "Session management not used in stateless mode." },
    id: null,
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  app.listen(PORT, () => {
    console.log(`Gmail MCP server listening on port ${PORT}`);
    console.log(`  MCP endpoint:  ${SERVER_URL}/mcp`);
    console.log(`  Setup page:    ${SERVER_URL}/setup`);
    console.log(`  Health check:  ${SERVER_URL}/health`);
    console.log(`  Accounts:      ${tokenStore.size}`);
  });
}
