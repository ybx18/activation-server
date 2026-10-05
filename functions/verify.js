export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const body = await request.json();
  const { code, deviceId, packageName, nonce, ts } = body;

  const codes = {
    'D2CD-9BA0-F334': { expiresAt: null, remainingUses: null }
  };
  const allowedPackages = ['com.example.app'];

  const record = codes[code?.toUpperCase()?.trim()];
  let ok = record !== null && nonce && allowedPackages.includes(packageName);
  let expiresAt = record?.expiresAt ?? null;
  let remainingUses = record?.remainingUses ?? null;

  if (expiresAt && expiresAt <= Date.now()) ok = false;

  // 从环境变量获取纯 Base64 私钥
  const privateKeyBase64 = env.PRIVATE_KEY;
  if (!privateKeyBase64) {
    return new Response(JSON.stringify({ error: 'Private key not configured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 代码里自动拼接 PEM 格式的头和尾
  const pem = `-----BEGIN EC PRIVATE KEY-----\n${privateKeyBase64.trim()}\n-----END EC PRIVATE KEY-----`;

  const pemHeader = "-----BEGIN EC PRIVATE KEY-----";
  const pemFooter = "-----END EC PRIVATE KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length).replace(/\s/g, '');

  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  const crypto = globalThis.crypto;
  const encoder = new TextEncoder();
  const payload = JSON.stringify({
    ok,
    expiresAt: expiresAt ?? 0,
    remainingUses: remainingUses ?? -1,
    nonce
  });

  const key = await crypto.subtle.importKey(
    "sec1",
    binaryDer.buffer,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    encoder.encode(payload)
  );

  const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));

  return new Response(JSON.stringify({
    ok,
    message: ok ? 'OK' : 'Invalid or expired code',
    expiresAt,
    remainingUses,
    nonce,
    sig: sigBase64
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}
