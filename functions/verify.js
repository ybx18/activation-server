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

  // 从环境变量获取十六进制私钥
  const privateKeyHex = env.PRIVATE_KEY_HEX;
  if (!privateKeyHex) {
    return new Response(JSON.stringify({ error: 'Private key not configured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 将 Hex 转换为 Uint8Array（无需再处理 PEM 头尾）
  const cleanHex = privateKeyHex.replace(/\s/g, '');
  const binaryDer = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    binaryDer[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }

  const crypto = globalThis.crypto;
  const encoder = new TextEncoder();
  const payload = JSON.stringify({
    ok,
    expiresAt: expiresAt ?? 0,
    remainingUses: remainingUses ?? -1,
    nonce
  });

  // 尝试使用 pkcs8 导入（如果报错，请改为 sec1 重新部署）
  const key = await crypto.subtle.importKey(
    "pkcs 8", 
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
