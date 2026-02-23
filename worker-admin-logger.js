export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
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

      if (request.method === "POST" && path === "/admin/request-otp") {
        return requestOTP(request, env);
      }

      if (request.method === "POST" && path === "/admin/verify-otp") {
        return verifyOTP(request, env);
      }

      return new Response("Not Found", { status: 404 });

    } catch (err) {
      return new Response("Server Error", { status: 500 });
    }
  }
};
async function requestOTP(request, env) {
  const { email, real_name, password } = await request.json();

  if (!email || !real_name || !password) {
    return new Response("Invalid Input", { status: 400 });
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

  const otp = generateOTP();

  await env.OTP_KV.put(`otp:${normalizedEmail}`, otp, { expirationTtl: 300 });

  await sendOTPEmail(normalizedEmail, otp);

  return new Response("OTP Sent", {
  headers: cors(env)
});
}
async function verifyOTP(request, env) {
  const { email, otp } = await request.json();
  const normalizedEmail = email.toLowerCase();

  const attemptKey = `otp_attempts:${normalizedEmail}`;
  const attempts = parseInt(await env.OTP_KV.get(attemptKey) || "0");

  if (attempts >= 5) {
    return new Response("Too Many Attempts", { status: 429 });
  }

  const storedOTP = await env.OTP_KV.get(`otp:${normalizedEmail}`);

  if (!storedOTP || storedOTP !== otp) {
    await env.OTP_KV.put(attemptKey, String(attempts + 1), { expirationTtl: 300 });
    return new Response("Invalid OTP", { status: 401 });
  }

  await env.OTP_KV.delete(`otp:${normalizedEmail}`);
  await env.OTP_KV.delete(attemptKey);

  const token = crypto.randomUUID();

  await env.SESSIONS.put(
    `session:${token}`,
    normalizedEmail,
    { expirationTtl: 86400 }
  );

  return new Response("Login Success", {
    headers: {
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
function generateOTP() {
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  return (array[0] % 90000 + 10000).toString();
}
async function sendOTPEmail(email, otp) {
  await fetch("https://api.mailchannels.net/tx/v1/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      personalizations: [{ to: [{ email }] }],
      from: {
        email: "admin@yourdomain.com",
        name: "Neon Anime Admin Login"
      },
      subject: "Valid OTP For Admin Login",
      content: [{
        type: "text/plain",
        value: `Among our respective Admins someone requested the access to manage our SQL database \n Your Valid OTP : ${otp}\n Will stay for 5 minutes.\n Thanks to be A Member Of Our Neon Community`
      }]
    })
  });
}
function json(data) {
  return new Response(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}
function cors(env) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
    "Access-Control-Allow-Credentials": "true"
  };
}
