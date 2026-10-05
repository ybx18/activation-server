// functions/verify.js
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

  // 从环境变量获取私钥
  const privateKey = env.PRIVATE_KEY;
  if (!privateKey) {
    return new Response(JSON.stringify({ error: 'Private key not configured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 使用 Web Crypto API 签名（无服务器环境不支持 node:crypto 的 sign）
  const crypto = globalThis.crypto;
  const encoder = new TextEncoder();
  const payload = JSON.stringify({
    ok,
    expiresAt: expiresAt ?? 0,
    remainingUses: remainingUses ?? -1,
    nonce
  });

  // 将 PEM 私钥转换为 CryptoKey
  const pemHeader = "-----BEGIN EC PRIVATE KEY-----";
  const pemFooter = "-----END EC PRIVATE KEY-----";
  const pemContents = privateKey.substring(pemHeader.length, privateKey.length - pemFooter.length);
  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  const key = await crypto.subtle.importKey(
    "pkcs8",
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

  // 将签名转为 Base64
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
