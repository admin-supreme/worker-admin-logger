export default {
  async fetch(request, env, ctx) {

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Allow-Credentials": "true"
        }
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {

      if (request.method === "POST" && path === "/admin/login") {
        return login(request, env);
      }

      return new Response("Not Found", {
        status: 404,
        headers: cors(env)
      });

    } catch (err) {
      return new Response("Server Error", {
        status: 500,
        headers: cors(env)
      });
    }
  }
};

async function login(request, env) {
  const { email, real_name, password } = await request.json();

  if (!email || !real_name || !password) {
    return new Response("Invalid Input", {
      status: 400,
      headers: cors(env)
    });
  }

  const normalizedEmail = email.toLowerCase();

  const { results } = await env.DB.prepare(`
    SELECT * FROM ultimate_admin
    WHERE email = ?
    LIMIT 1
  `).bind(normalizedEmail).all();

  if (!results.length) {
    return new Response("Unauthorized", {
      status: 401,
      headers: cors(env)
    });
  }

  const admin = results[0];

  if (admin.real_name !== real_name.toLowerCase()) {
    return new Response("Unauthorized", {
      status: 401,
      headers: cors(env)
    });
  }

  const valid = await verifyPassword(password, admin.password_hash);
  if (!valid) {
    return new Response("Unauthorized", {
      status: 401,
      headers: cors(env)
    });
  }

  const token = crypto.randomUUID();

  await env.SESSIONS.put(
    `session:${token}`,
    normalizedEmail,
    { expirationTtl: 86400 }
  );

  return new Response("Login Success", {
    headers: {
      ...cors(env),
      "Set-Cookie": `admin_session=${token}; HttpOnly; Secure; SameSite=None; Path=/`
    }
  });
}

async function verifyPassword(password, storedHash) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);

  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

  return constantTimeEqual(hashHex, storedHash);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function cors(env) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
    "Access-Control-Allow-Credentials": "true"
  };
}
