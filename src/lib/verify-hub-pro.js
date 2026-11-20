// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// Pro JWT verifier: same algorithm the Pro hub signs with.
// Verify-only: apps never mint, only the hub does.
// Spec field shape: { v: 1, email, pro_until, iss: 'app-hub', iat, exp }

const ISS = 'app-hub';
const V = 1;

function b64urlDecode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - str.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function importKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
}

export async function verifyHubPro(token, secret) {
  if (!token || !secret) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;

  try {
    const key = await importKey(secret);
    const sigBytes = b64urlDecode(sigB64);
    const valid = await crypto.subtle.verify(
      'HMAC', key, sigBytes,
      new TextEncoder().encode(`${headerB64}.${payloadB64}`)
    );
    if (!valid) return null;

    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64)));
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp < now) return null;
    if (payload.iss !== ISS) return null;
    if (payload.v !== V) return null;
    if (!payload.email) return null;
    // pro_until is optional: null = free-user SSO token (valid identity, no Pro entitlement).
    // Pro feature gating elsewhere already checks pro_until > now, so null falls back to free.
    if (payload.pro_until && new Date(payload.pro_until).getTime() < Date.now()) return null;

    return payload;
  } catch {
    return null;
  }
}
