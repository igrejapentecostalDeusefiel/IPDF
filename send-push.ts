// @ts-nocheck
// Supabase Edge Function — send-push (sem dependências externas)
// Secrets:
//   VAPID_PUBLIC_KEY  = BEK2luLPeo_evRbHeBHI-BSU8aC8vAZmuzfJyv4hPKViBHNhN5W7l6oOGDczUpbX53Ve-WEqG9WLnyLyVoxMaAw
//   VAPID_PRIVATE_KEY = jQNChZgapcp9p2ikGlIZ2BgA-i_tu27Kf2Vy1PhANbY
//   VAPID_SUBJECT     = mailto:igrejapentecostaldeusefiel9@gmail.com

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// ── helpers ──────────────────────────────────────────────────────────────────

function b64u(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function fromb64u(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let i = 0;
  for (const a of arrays) { out.set(a, i); i += a.length; }
  return out;
}

const enc = s => new TextEncoder().encode(s);

// ── VAPID JWT (ES256) ─────────────────────────────────────────────────────────

async function vapidJWT(aud, subject, pubB64, privB64) {
  const header  = b64u(enc(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const payload = b64u(enc(JSON.stringify({
    aud, sub: subject,
    exp: Math.floor(Date.now() / 1000) + 43200,
  })));
  const data = enc(`${header}.${payload}`);

  // Importa chave privada EC P-256 via JWK (mais confiável que PKCS8 manual)
  const privBytes = fromb64u(privB64);
  const pubBytes  = fromb64u(pubB64);

  // Decompõe a chave pública (0x04 + 32 bytes X + 32 bytes Y)
  const x = b64u(pubBytes.slice(1, 33));
  const y = b64u(pubBytes.slice(33, 65));
  const d = b64u(privBytes);

  const privKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x, y, d, key_ops: ["sign"] },
    { name: "ECDSA", namedCurve: "P-256" },
    false, ["sign"]
  );

  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privKey, data
  );

  return `${header}.${payload}.${b64u(sig)}`;
}

// ── RFC 8291 encryption (aesgcm) ──────────────────────────────────────────────

async function hkdf(ikm, salt, info, len) {
  const key  = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8
  );
  return new Uint8Array(bits);
}

async function encrypt(sub, payloadStr) {
  const clientPub  = fromb64u(sub.p256dh);
  const authSecret = fromb64u(sub.auth);
  const salt       = crypto.getRandomValues(new Uint8Array(16));

  // Gera par efêmero
  const serverPair   = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
  const serverPubRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", serverPair.publicKey)
  );

  // ECDH shared secret
  const clientKey = await crypto.subtle.importKey(
    "raw", clientPub, { name: "ECDH", namedCurve: "P-256" }, false, []
  );
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: clientKey }, serverPair.privateKey, 256
    )
  );

  // PRK via HKDF
  const prk = await hkdf(shared, authSecret, enc("Content-Encoding: auth\0"), 32);

  // Context
  const ctx = concat(
    enc("P-256\0"),
    new Uint8Array([0, 65]), clientPub,
    new Uint8Array([0, 65]), serverPubRaw,
  );

  const cek   = await hkdf(prk, salt, concat(enc("Content-Encoding: aesgcm\0"), ctx), 16);
  const nonce = await hkdf(prk, salt, concat(enc("Content-Encoding: nonce\0"),  ctx), 12);

  // AES-GCM encrypt
  const aesKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const plain  = concat(new Uint8Array([0, 0]), enc(payloadStr));
  const body   = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, plain)
  );

  return {
    body,
    encHeaders: {
      "Content-Encoding": "aesgcm",
      "Encryption":  `salt=${b64u(salt)}`,
      "Crypto-Key":  `dh=${b64u(serverPubRaw)}`,
    },
  };
}

// ── Envia para um endpoint ────────────────────────────────────────────────────

async function sendOne(sub, payloadStr, jwt, pubB64) {
  if (!sub.endpoint?.startsWith("http")) {
    console.log("Endpoint manual ignorado:", sub.endpoint);
    return { ok: false, manual: true };
  }

  const { body, encHeaders } = await encrypt(sub, payloadStr);
  const { protocol, host }   = new URL(sub.endpoint);

  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      ...encHeaders,
      "Authorization": `vapid t=${jwt}, k=${pubB64}`,
      "Content-Type":  "application/octet-stream",
      "TTL":           "86400",
    },
    body,
  });

  const text = await res.text().catch(() => "");
  console.log(`FCM status ${res.status}:`, text.slice(0, 200));

  if (res.status === 410 || res.status === 404) {
    console.log("Endpoint expirado:", sub.endpoint);
    return { ok: false, expired: true };
  }
  return { ok: res.ok, status: res.status };
}

// ── Handler ───────────────────────────────────────────────────────────────────

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  try {
    const PUB  = Deno.env.get("VAPID_PUBLIC_KEY")  ?? "";
    const PRIV = Deno.env.get("VAPID_PRIVATE_KEY") ?? "";
    const SUB  = Deno.env.get("VAPID_SUBJECT")     ?? "mailto:admin@ipdf.com";

    if (!PUB || !PRIV) {
      return new Response(JSON.stringify({ error: "VAPID keys não configuradas." }), {
        status: 500, headers: { ...CORS, "Content-Type": "application/json" },
      });
    }

    const { titulo, mensagem, tipo, icone, url, subscriptions = [] } = await req.json();

    console.log(`Enviando para ${subscriptions.length} inscrições...`);

    const payloadStr = JSON.stringify({
      titulo:   titulo   ?? "IPDF",
      mensagem: mensagem ?? "",
      tipo:     tipo     ?? "geral",
      icone:    icone    ?? "/Logo-IPDF.png",
      url:      url      ?? "/IPDF/",
    });

    let enviados = 0, erros = 0;

    // Gera JWT por audiência (FCM usa a mesma)
    const jwtCache = {};
    async function getJWT(endpoint) {
      const { protocol, host } = new URL(endpoint);
      const aud = `${protocol}//${host}`;
      if (!jwtCache[aud]) jwtCache[aud] = await vapidJWT(aud, SUB, PUB, PRIV);
      return jwtCache[aud];
    }

    const BATCH = 20;
    for (let i = 0; i < subscriptions.length; i += BATCH) {
      await Promise.all(
        subscriptions.slice(i, i + BATCH).map(async (sub) => {
          try {
            if (!sub.endpoint?.startsWith("http")) { erros++; return; }
            const jwt = await getJWT(sub.endpoint);
            const res = await sendOne(sub, payloadStr, jwt, PUB);
            res.ok ? enviados++ : erros++;
          } catch (e) {
            console.error("Exceção:", String(e));
            erros++;
          }
        })
      );
    }

    console.log(`Resultado: ${enviados} enviados, ${erros} erros`);
    return new Response(JSON.stringify({ enviados, erros }), {
      headers: { ...CORS, "Content-Type": "application/json" },
    });

  } catch (e) {
    console.error("Erro geral:", String(e));
    return new Response(JSON.stringify({ error: String(e) }), {
      status: 500, headers: { ...CORS, "Content-Type": "application/json" },
    });
  }
});
