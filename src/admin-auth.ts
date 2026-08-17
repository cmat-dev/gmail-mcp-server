import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export interface AdminSession {
  version: 1;
  sessionId: string;
  csrfToken: string;
  expiresAt: number;
  passwordVersion: string;
}

interface OAuthStateRecord {
  sessionId: string;
  expiresAt: number;
}

interface LoginAttemptRecord {
  failures: number;
  windowExpiresAt: number;
}

export interface AdminAuthOptions {
  adminPassword: string;
  sessionSecret: string;
  secureCookie: boolean;
  sessionTtlMs?: number;
  oauthStateTtlMs?: number;
  loginWindowMs?: number;
  maxLoginAttempts?: number;
  now?: () => number;
}

const DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000;
const DEFAULT_OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const DEFAULT_LOGIN_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_MAX_LOGIN_ATTEMPTS = 5;

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function safeEqual(left: string, right: string): boolean {
  return timingSafeEqual(digest(left), digest(right));
}

function parseCookies(cookieHeader: string | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  if (!cookieHeader) return cookies;

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;

    const name = part.slice(0, separator).trim();
    const encodedValue = part.slice(separator + 1).trim();
    try {
      cookies.set(name, decodeURIComponent(encodedValue));
    } catch {
      // Ignore malformed cookie values.
    }
  }

  return cookies;
}

export class AdminAuth {
  readonly cookieName: string;
  readonly sessionCookieOptions: {
    httpOnly: true;
    secure: boolean;
    sameSite: "lax";
    path: "/";
    maxAge: number;
  };

  private readonly adminPassword: string;
  private readonly sessionKey: Buffer;
  private readonly passwordVersion: string;
  private readonly sessionTtlMs: number;
  private readonly oauthStateTtlMs: number;
  private readonly loginWindowMs: number;
  private readonly maxLoginAttempts: number;
  private readonly now: () => number;
  private readonly oauthStates = new Map<string, OAuthStateRecord>();
  private readonly loginAttempts = new Map<string, LoginAttemptRecord>();

  constructor(options: AdminAuthOptions) {
    if (!options.adminPassword) {
      throw new Error("ADMIN_PASSWORD environment variable is required");
    }
    if (!options.sessionSecret) {
      throw new Error("SESSION_SECRET or ENCRYPTION_KEY environment variable is required");
    }

    this.adminPassword = options.adminPassword;
    this.sessionKey = createHmac("sha256", options.sessionSecret)
      .update("gmail-mcp-admin-session-v1")
      .digest();
    this.passwordVersion = digest(options.adminPassword).toString("hex").slice(0, 16);
    this.sessionTtlMs = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
    this.oauthStateTtlMs = options.oauthStateTtlMs ?? DEFAULT_OAUTH_STATE_TTL_MS;
    this.loginWindowMs = options.loginWindowMs ?? DEFAULT_LOGIN_WINDOW_MS;
    this.maxLoginAttempts = options.maxLoginAttempts ?? DEFAULT_MAX_LOGIN_ATTEMPTS;
    this.now = options.now ?? Date.now;

    this.cookieName = options.secureCookie
      ? "__Host-gmail_mcp_admin"
      : "gmail_mcp_admin";
    this.sessionCookieOptions = {
      httpOnly: true,
      secure: options.secureCookie,
      sameSite: "lax",
      path: "/",
      maxAge: this.sessionTtlMs,
    };
  }

  verifyPassword(candidate: unknown): boolean {
    return typeof candidate === "string" && safeEqual(candidate, this.adminPassword);
  }

  createSession(): { session: AdminSession; token: string } {
    const session: AdminSession = {
      version: 1,
      sessionId: randomBytes(24).toString("base64url"),
      csrfToken: randomBytes(24).toString("base64url"),
      expiresAt: this.now() + this.sessionTtlMs,
      passwordVersion: this.passwordVersion,
    };

    return { session, token: this.signSession(session) };
  }

  readSession(cookieHeader: string | undefined): AdminSession | null {
    const token = parseCookies(cookieHeader).get(this.cookieName);
    if (!token) return null;

    const separator = token.lastIndexOf(".");
    if (separator < 1) return null;

    const payload = token.slice(0, separator);
    const suppliedSignature = token.slice(separator + 1);
    const expectedSignature = this.sign(payload);
    if (!safeEqual(suppliedSignature, expectedSignature)) return null;

    try {
      const parsed = JSON.parse(
        Buffer.from(payload, "base64url").toString("utf8")
      ) as Partial<AdminSession>;

      if (
        parsed.version !== 1 ||
        typeof parsed.sessionId !== "string" ||
        typeof parsed.csrfToken !== "string" ||
        typeof parsed.expiresAt !== "number" ||
        typeof parsed.passwordVersion !== "string" ||
        parsed.expiresAt <= this.now() ||
        !safeEqual(parsed.passwordVersion, this.passwordVersion)
      ) {
        return null;
      }

      return parsed as AdminSession;
    } catch {
      return null;
    }
  }

  verifyCsrf(session: AdminSession, suppliedToken: unknown): boolean {
    return (
      typeof suppliedToken === "string" &&
      safeEqual(suppliedToken, session.csrfToken)
    );
  }

  createOAuthState(session: AdminSession): string {
    this.pruneExpiredState();
    const state = randomBytes(32).toString("base64url");
    this.oauthStates.set(state, {
      sessionId: session.sessionId,
      expiresAt: this.now() + this.oauthStateTtlMs,
    });
    return state;
  }

  consumeOAuthState(state: unknown, session: AdminSession): boolean {
    if (typeof state !== "string") return false;

    const record = this.oauthStates.get(state);
    this.oauthStates.delete(state);
    if (!record || record.expiresAt <= this.now()) return false;

    return safeEqual(record.sessionId, session.sessionId);
  }

  isLoginBlocked(clientId: string): boolean {
    const record = this.loginAttempts.get(clientId);
    if (!record) return false;
    if (record.windowExpiresAt <= this.now()) {
      this.loginAttempts.delete(clientId);
      return false;
    }
    return record.failures >= this.maxLoginAttempts;
  }

  recordLoginFailure(clientId: string): void {
    const existing = this.loginAttempts.get(clientId);
    if (!existing || existing.windowExpiresAt <= this.now()) {
      this.loginAttempts.set(clientId, {
        failures: 1,
        windowExpiresAt: this.now() + this.loginWindowMs,
      });
      return;
    }
    existing.failures += 1;
  }

  clearLoginFailures(clientId: string): void {
    this.loginAttempts.delete(clientId);
  }

  private signSession(session: AdminSession): string {
    const payload = Buffer.from(JSON.stringify(session)).toString("base64url");
    return `${payload}.${this.sign(payload)}`;
  }

  private sign(payload: string): string {
    return createHmac("sha256", this.sessionKey)
      .update(payload)
      .digest("base64url");
  }

  private pruneExpiredState(): void {
    const now = this.now();
    for (const [state, record] of this.oauthStates) {
      if (record.expiresAt <= now) this.oauthStates.delete(state);
    }
  }
}
