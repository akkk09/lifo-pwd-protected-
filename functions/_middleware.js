const ITERATIONS = 600_000;
const encoder = new TextEncoder();

function fromHex(value) {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value ?? "")) return null;
  return Uint8Array.from(value.match(/.{2}/g), byte => parseInt(byte, 16));
}

function fromBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value ?? "")) return null;
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function deriveHash(value, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(value),
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: ITERATIONS,
    },
    key,
    256,
  );

  return new Uint8Array(bits);
}

function constantTimeEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;

  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference === 0;
}

export async function onRequest({ request, env, next }) {
  const salt = fromBase64Url(env.SITE_AUTH_SALT);
  const expectedUsernameHash = fromHex(env.SITE_USERNAME_HASH);
  const expectedPasswordHash = fromHex(env.SITE_PASSWORD_HASH);
  const authorization = request.headers.get("Authorization");

  if (
    salt &&
    expectedUsernameHash &&
    expectedPasswordHash &&
    authorization?.startsWith("Basic ")
  ) {
    try {
      const binary = atob(authorization.slice(6));
      const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
      const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      const separator = decoded.indexOf(":");

      if (separator !== -1) {
        const username = decoded.slice(0, separator);
        const password = decoded.slice(separator + 1);

        const [usernameHash, passwordHash] = await Promise.all([
          deriveHash("lifo-username:" + username, salt),
          deriveHash("lifo-password:" + password, salt),
        ]);

        if (
          constantTimeEqual(usernameHash, expectedUsernameHash) &&
          constantTimeEqual(passwordHash, expectedPasswordHash)
        ) {
          return next();
        }
      }
    } catch {
      // Malformed credentials or invalid encoding: deny access.
    }
  }

  return new Response("Authentication required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Lifo", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
}
