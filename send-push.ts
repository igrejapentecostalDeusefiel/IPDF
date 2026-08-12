// @ts-nocheck
// Supabase Edge Function — send-push
// Cole este arquivo no editor da Edge Function no painel do Supabase.
// Não é um arquivo Node.js — roda no Deno (runtime do Supabase).
//
// Secrets necessários (Supabase → Settings → Edge Functions → Secrets):
//   VAPID_PUBLIC_KEY  = BEK2luLPeo_evRbHeBHI-BSU8aC8vAZmuzfJyv4hPKViBHNhN5W7l6oOGDczUpbX53Ve-WEqG9WLnyLyVoxMaAw
//   VAPID_PRIVATE_KEY = jQNChZgapcp9p2ikGlIZ2BgA-i_tu27Kf2Vy1PhANbY
//   VAPID_SUBJECT     = mailto:seu@email.com

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// ---- Helpers base64url ----
function b64uToBytes(b64) {
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const std = (b64 + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(std), (c) => c.charCodeAt(0));
}

function bytesToB64u(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ---- Converte chave privada raw (32 bytes) para PKCS#8 ----
function rawPrivToPkcs8(raw) {
  // Template PKCS#8 para EC P-256 com 32 bytes de chave privada
  const header = new Uint8Array([
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
  ]);
  const out = new Uint8Array(header.length + raw.length);
  out.set(header);
  out.set(raw, header.length);
  return out.buffer;
}

// ---- JWT VAPID ----
async function makeVapidHeader(audience, subject, pubB64, privB64) {
  const now = Math.floor(Date.now() / 1000);
  const jwt_header  = bytesToB64u(new TextEncoder().encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const jwt_payload = bytesToB64u(new TextEncoder().encode(JSON.stringify({ aud: audience, exp: now + 43200, sub: subject })));
  const sigInput    = `${jwt_header}.${jwt_payload}`;

  const privKey = await crypto.subtle.importKey(
    "pkcs8", rawPrivToPkcs8(b64uToBytes(privB64)),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privKey,
    new TextEncoder().encode(sigInput)
  );

  return `vapid t=${sigInput}.${bytesToB64u(sig)}, k=${pubB64}`;
}

// ---- Criptografia RFC8291 (aesgcm) ----
async function hkdf(ikm, salt, info, len) {
  const key  = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8);
  return new Uint8Array(bits);
}

async function encryptPayload(sub, payloadStr) {
  const clientPub    = b64uToBytes(sub.p256dh);
  const authSecret   = b64uToBytes(sub.auth);
  const salt         = crypto.getRandomValues(new Uint8Array(16));

  const serverPair   = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const serverPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", serverPair.publicKey));

  const clientKey    = await crypto.subtle.importKey("raw", clientPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const sharedRaw    = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: clientKey }, serverPair.privateKey, 256));

  const prk = await hkdf(
    sharedRaw, authSecret,
    new TextEncoder().encode("Content-Encoding: auth\0"), 32
  );

  const ctx = new Uint8Array([
    ...new TextEncoder().encode("P-256\0"),
    0, 65, ...clientPub,
    0, 65, ...serverPubRaw,
  ]);

  const cek   = await hkdf(prk, salt, new Uint8Array([...new TextEncoder().encode("Content-Encoding: aesgcm\0"), ...ctx]), 16);
  const nonce = await hkdf(prk, salt, new Uint8Array([...new TextEncoder().encode("Content-Encoding: nonce\0"), ...ctx]),  12);

  const aesKey    = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const plaintext = new Uint8Array([0, 0, ...new TextEncoder().encode(payloadStr)]);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, plaintext));

  return {
    body: encrypted,
    headers: {
      "Content-Encoding": "aesgcm",
      "Encryption":  `salt=${bytesToB64u(salt)}`,
      "Crypto-Key":  `dh=${bytesToB64u(serverPubRaw)}`,
    },
  };
}

// ---- Envia para um endpoint ----
async function sendOne(sub, payloadStr, vapidHeader) {
  if (!sub.endpoint || !sub.endpoint.startsWith("http")) {
    return { ok: true, manual: true }; // inscrição sem SW real — conta como enviado
  }
  try {
    const { body, headers } = await encryptPayload(sub, payloadStr);
    const res = await fetch(sub.endpoint, {
      method:  "POST",
      headers: { ...headers, "Authorization": vapidHeader, "Content-Type": "application/octet-stream", "TTL": "86400" },
      body,
    });
    // 410 Gone = endpoint expirado, ignora
    return { ok: res.ok || res.status === 410, status: res.status };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

// ---- Handler ----
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

    const { titulo, mensagem, tipo, icone, url, subscriptions } = await req.json();
    const payloadStr = JSON.stringify({ titulo, mensagem, tipo, icone: icone ?? "/Logo-IPDF.png", url: url ?? "/" });

    let enviados = 0, erros = 0;
    const vapidCache = {};

    async function vapidFor(endpoint) {
      const { protocol, host } = new URL(endpoint);
      const aud = `${protocol}//${host}`;
      if (!vapidCache[aud]) vapidCache[aud] = await makeVapidHeader(aud, SUB, PUB, PRIV);
      return vapidCache[aud];
    }

    const BATCH = 50;
    for (let i = 0; i < (subscriptions ?? []).length; i += BATCH) {
      await Promise.all(
        subscriptions.slice(i, i + BATCH).map(async (sub) => {
          try {
            const vh  = sub.endpoint?.startsWith("http") ? await vapidFor(sub.endpoint) : "";
            const res = await sendOne(sub, payloadStr, vh);
            res.ok ? enviados++ : erros++;
          } catch {
            erros++;
          }
        })
      );
    }

    return new Response(JSON.stringify({ enviados, erros }), {
      headers: { ...CORS, "Content-Type": "application/json" },
    });

  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), {
      status: 500, headers: { ...CORS, "Content-Type": "application/json" },
    });
  }
});
