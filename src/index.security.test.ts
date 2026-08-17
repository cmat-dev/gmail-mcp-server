import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after, before } from "node:test";
import type { Server } from "node:http";

const dataDirectory = mkdtempSync(join(tmpdir(), "gmail-mcp-security-test-"));
const testPassword = "test-only admin password";

Object.assign(process.env, {
  ADMIN_PASSWORD: testPassword,
  ENCRYPTION_KEY: "test-only encryption key with enough entropy",
  GOOGLE_CLIENT_ID: "test-client-id",
  GOOGLE_CLIENT_SECRET: "test-client-secret",
  SERVER_URL: "https://gmail-mcp.example.test",
  DATA_DIR: dataDirectory,
  NODE_ENV: "test",
});

const { app } = await import("./index.js");

let server: Server;
let baseUrl: string;

before(async () => {
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Test server did not bind to a TCP port");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  rmSync(dataDirectory, { recursive: true, force: true });
});

test("legacy key URLs are stripped and never create a session", async () => {
  const response = await fetch(`${baseUrl}/setup?key=legacy-secret`, {
    redirect: "manual",
  });

  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "/setup");
  assert.equal(response.headers.get("set-cookie"), null);
});

test("login uses POST and returns a hardened session cookie", async () => {
  const loginPage = await fetch(`${baseUrl}/setup`);
  const loginHtml = await loginPage.text();

  assert.equal(loginPage.status, 401);
  assert.match(loginHtml, /method="POST" action="\/setup\/login"/);
  assert.doesNotMatch(loginHtml, /name="key"/);
  assert.equal(loginPage.headers.get("cache-control"), "no-store, max-age=0");
  assert.match(loginPage.headers.get("content-security-policy") ?? "", /default-src 'none'/);

  const response = await fetch(`${baseUrl}/setup/login`, {
    method: "POST",
    body: new URLSearchParams({ password: testPassword }),
    redirect: "manual",
  });
  const setCookie = response.headers.get("set-cookie") ?? "";

  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "/setup");
  assert.match(setCookie, /^__Host-gmail_mcp_admin=/);
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /Secure/i);
  assert.match(setCookie, /SameSite=Lax/i);
  assert.match(setCookie, /Path=\//i);
  assert.doesNotMatch(setCookie, new RegExp(testPassword));
});

test("authenticated mutations require CSRF and OAuth state is one-time", async () => {
  const login = await fetch(`${baseUrl}/setup/login`, {
    method: "POST",
    body: new URLSearchParams({ password: testPassword }),
    redirect: "manual",
  });
  const cookie = (login.headers.get("set-cookie") ?? "").split(";", 1)[0];
  assert.ok(cookie);

  const setup = await fetch(`${baseUrl}/setup`, {
    headers: { cookie },
  });
  const setupHtml = await setup.text();
  const csrfToken = setupHtml.match(/name="csrfToken" value="([^"]+)"/)?.[1];
  assert.equal(setup.status, 200);
  assert.ok(csrfToken);

  const missingCsrf = await fetch(`${baseUrl}/setup/remove`, {
    method: "POST",
    headers: { cookie },
    body: new URLSearchParams({ email: "nobody@example.test" }),
    redirect: "manual",
  });
  assert.equal(missingCsrf.status, 403);

  const oauthStart = await fetch(`${baseUrl}/oauth/start`, {
    method: "POST",
    headers: { cookie },
    body: new URLSearchParams({ csrfToken }),
    redirect: "manual",
  });
  const oauthLocation = oauthStart.headers.get("location");
  assert.equal(oauthStart.status, 302);
  assert.ok(oauthLocation);

  const state = new URL(oauthLocation).searchParams.get("state");
  assert.ok(state);
  assert.notEqual(state, testPassword);
  assert.ok(state.length >= 32);

  const callback = await fetch(
    `${baseUrl}/oauth/callback?error=access_denied&state=${encodeURIComponent(state)}`,
    { headers: { cookie }, redirect: "manual" }
  );
  assert.equal(callback.status, 303);
  assert.doesNotMatch(callback.headers.get("location") ?? "", new RegExp(testPassword));

  const replay = await fetch(
    `${baseUrl}/oauth/callback?error=access_denied&state=${encodeURIComponent(state)}`,
    { headers: { cookie }, redirect: "manual" }
  );
  assert.equal(replay.status, 400);
});
