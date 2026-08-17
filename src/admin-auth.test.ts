import assert from "node:assert/strict";
import test from "node:test";
import { AdminAuth } from "./admin-auth.js";

function makeAuth(overrides: Partial<ConstructorParameters<typeof AdminAuth>[0]> = {}) {
  return new AdminAuth({
    adminPassword: "correct horse battery staple",
    sessionSecret: "a separate high entropy session secret",
    secureCookie: true,
    ...overrides,
  });
}

test("verifies the admin password without accepting non-string values", () => {
  const auth = makeAuth();
  assert.equal(auth.verifyPassword("correct horse battery staple"), true);
  assert.equal(auth.verifyPassword("wrong"), false);
  assert.equal(auth.verifyPassword(undefined), false);
});

test("creates a signed, time-limited session in a hardened cookie", () => {
  let now = 1_000;
  const auth = makeAuth({ sessionTtlMs: 5_000, now: () => now });
  const { session, token } = auth.createSession();
  const cookie = `${auth.cookieName}=${encodeURIComponent(token)}`;

  assert.deepEqual(auth.readSession(cookie), session);
  assert.deepEqual(auth.sessionCookieOptions, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 5_000,
  });

  now = 6_001;
  assert.equal(auth.readSession(cookie), null);
});

test("rejects tampered sessions and sessions issued before a password rotation", () => {
  const original = makeAuth();
  const { token } = original.createSession();
  const cookie = `${original.cookieName}=${encodeURIComponent(token)}`;
  const tampered = `${original.cookieName}=${encodeURIComponent(`${token}x`)}`;

  assert.equal(original.readSession(tampered), null);

  const rotated = makeAuth({ adminPassword: "new unique admin password" });
  assert.equal(rotated.readSession(cookie), null);
});

test("requires the CSRF token stored in the authenticated session", () => {
  const auth = makeAuth();
  const { session } = auth.createSession();

  assert.equal(auth.verifyCsrf(session, session.csrfToken), true);
  assert.equal(auth.verifyCsrf(session, "wrong"), false);
});

test("OAuth state is one-time, expiring, and bound to the initiating session", () => {
  let now = 1_000;
  const auth = makeAuth({ oauthStateTtlMs: 5_000, now: () => now });
  const firstSession = auth.createSession().session;
  const secondSession = auth.createSession().session;

  const wrongSessionState = auth.createOAuthState(firstSession);
  assert.equal(auth.consumeOAuthState(wrongSessionState, secondSession), false);
  assert.equal(auth.consumeOAuthState(wrongSessionState, firstSession), false);

  const validState = auth.createOAuthState(firstSession);
  assert.equal(auth.consumeOAuthState(validState, firstSession), true);
  assert.equal(auth.consumeOAuthState(validState, firstSession), false);

  const expiredState = auth.createOAuthState(firstSession);
  now = 6_001;
  assert.equal(auth.consumeOAuthState(expiredState, firstSession), false);
});

test("throttles repeated failed logins and resets after success or expiry", () => {
  let now = 1_000;
  const auth = makeAuth({
    maxLoginAttempts: 2,
    loginWindowMs: 5_000,
    now: () => now,
  });

  assert.equal(auth.isLoginBlocked("client"), false);
  auth.recordLoginFailure("client");
  assert.equal(auth.isLoginBlocked("client"), false);
  auth.recordLoginFailure("client");
  assert.equal(auth.isLoginBlocked("client"), true);

  auth.clearLoginFailures("client");
  assert.equal(auth.isLoginBlocked("client"), false);

  auth.recordLoginFailure("client");
  auth.recordLoginFailure("client");
  now = 6_001;
  assert.equal(auth.isLoginBlocked("client"), false);
});
