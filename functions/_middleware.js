
async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hash))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequest({ request, env, next }) {
  const auth = request.headers.get("Authorization");

  if (auth?.startsWith("Basic ")) {
    try {
      const decoded = atob(auth.slice(6));
      const credentials = new TextDecoder().decode(
        Uint8Array.from(decoded, c => c.charCodeAt(0))
      );

      const separator = credentials.indexOf(":");

      if (separator !== -1) {
        const username = credentials.slice(0, separator);
        const password = credentials.slice(separator + 1);

        const [userHash, passHash] = await Promise.all([
          sha256(username),
          sha256(password),
        ]);

        if (
          userHash === env.SITE_USERNAME_HASH &&
          passHash === env.SITE_PASSWORD_HASH
        ) {
          return next();
        }
      }
    } catch {
      // Reject malformed credentials.
    }
  }

  return new Response("Authentication required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Lifo"',
      "Cache-Control": "no-store",
    },
  });
}
