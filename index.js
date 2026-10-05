const express = require('express');
const app = express();
app.use(express.json());

// 你的激活码逻辑（生产环境建议替换为数据库查询）
const codes = {
  'D2CD-9BA0-F334': { expiresAt: null, remainingUses: null }
};
const allowedPackages = ['com.example.app'];

app.post('/activation/verify', (req, res) => {
  const { code, deviceId, packageName, nonce, ts } = req.body;
  const record = codes[code?.toUpperCase()?.trim()];

  let ok = record !== null && nonce && allowedPackages.includes(packageName);
  let expiresAt = record?.expiresAt ?? null;
  let remainingUses = record?.remainingUses ?? null;

  if (expiresAt && expiresAt <= Date.now()) ok = false;

  // ⚠️ 注意：此处私钥从环境变量读取，不要硬编码在代码里！
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    return res.status(500).json({ error: 'Private key not configured' });
  }

  const crypto = require('crypto');
  const signedPayload = JSON.stringify({
    ok,
    expiresAt: expiresAt ?? 0,
    remainingUses: remainingUses ?? -1,
    nonce
  });

  const sign = crypto.createSign('SHA256');
  sign.update(signedPayload);
  sign.end();
  const sig = sign.sign(privateKey).toString('base64');

  res.json({
    ok,
    message: ok ? 'OK' : 'Invalid or expired code',
    expiresAt,
    remainingUses,
    nonce,
    sig
  });
});

const port = process.env.PORT || 8088;
app.listen(port, () => console.log(`Server running on port ${port}`));
