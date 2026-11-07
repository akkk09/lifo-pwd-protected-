export async function onRequest({ request, env, next }) {
  const authorization = request.headers.get("Authorization");

  if (authorization?.startsWith("Basic ")) {
    try {
      const decoded = atob(authorization.slice(6));
      const separator = decoded.indexOf(":");

      if (separator !== -1) {
        const username = decoded.slice(0, separator);
        const password = decoded.slice(separator + 1);

        if (
          username === env.SITE_USERNAME &&
          password === env.SITE_PASSWORD
        ) {
          return next();
        }
      }
    } catch {
      // Treat malformed credentials as unauthenticated.
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
