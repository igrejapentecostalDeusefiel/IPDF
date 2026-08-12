// @ts-nocheck
// Supabase Edge Function — send-push
// Secrets necessários (Supabase → Settings → Edge Functions → Secrets):
//   VAPID_PUBLIC_KEY  = BEK2luLPeo_evRbHeBHI-BSU8aC8vAZmuzfJyv4hPKViBHNhN5W7l6oOGDczUpbX53Ve-WEqG9WLnyLyVoxMaAw
//   VAPID_PRIVATE_KEY = jQNChZgapcp9p2ikGlIZ2BgA-i_tu27Kf2Vy1PhANbY
//   VAPID_SUBJECT     = mailto:seu@email.com

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// ---- base64url helpers ----
function b64uToBytes(b64) {
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const std = (b64 + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(std), (c) => c.charCodeAt(0));
}

function bytesToB64u(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ---- Importa chave privada EC P-256 a partir de raw bytes (32 bytes) ----
// Monta o envelope PKCS#8 correto para P-256
async function importPrivateKey(privB64) {
  const privBytes = b64uToBytes(privB64);

  // PKCS#8 DER para EC P-256 — estrutura completa e correta
  // Referência: RFC 5958 + SEC1
  const der = new Uint8Array([
    0x30, 0x81, 0x87,           // SEQUENCE (135 bytes)
      0x02, 0x01, 0x00,         // INTEGER version = 0
      0x30, 0x13,               // SEQUENCE algorithmIdentifier
        0x06, 0x07,             // OID id-ecPublicKey
          0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08,             // OID prime256v1 (P-256)
          0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
      0x04, 0x6d,               // OCTET STRING (109 bytes)
        0x30, 0x6b,             // SEQUENCE ECPrivateKey
          0x02, 0x01, 0x01,     // INTEGER version = 1
          0x04, 0x20,           // OCTET STRING (32 bytes) — chave privada
            ...privBytes,
          0xa1, 0x44,           // [1] EXPLICIT publicKey
            0x03, 0x42,         // BIT STRING (66 bytes)
              0x00,             // padding bits = 0
              // publicKey placeholder — não usado pela SubtleCrypto para sign
              0x04,
              ...new Uint8Array(64), // 64 zeros — SubtleCrypto não valida isso para import pkcs8+sign
  ]);

  return crypto.subtle.importKey(
    "pkcs8", der.buffer,
    { name: "ECDSA", namedCurve: "P-256" },
    false, ["sign"]
  );
}

// ---- JWT VAPID ----
async function makeVapidHeader(audience, subject, pubB64, privB64) {
  const now = Math.floor(Date.now() / 1000);
  const hdr = bytesToB64u(new TextEncoder().encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const pld = bytesToB64u(new TextEncoder().encode(JSON.stringify({ aud: audience, exp: now + 43200, sub: subject })));
  const msg = `${hdr}.${pld}`;

  const privKey = await importPrivateKey(privB64);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privKey, new TextEncoder().encode(msg));

  return `vapid t=${msg}.${bytesToB64u(sig)}, k=${pubB64}`;
}

// ---- HKDF ----
async function hkdf(ikm, salt, info, len) {
  const key  = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8);
  return new Uint8Array(bits);
}

// ---- Cifra RFC 8291 (aesgcm / draft-ietf-webpush-encryption) ----
async function encryptPayload(sub, payloadStr) {
  const clientPub  = b64uToBytes(sub.p256dh);
  const authSecret = b64uToBytes(sub.auth);
  const salt       = crypto.getRandomValues(new Uint8Array(16));

  const serverPair   = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const serverPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", serverPair.publicKey));

  const clientKey  = await crypto.subtle.importKey("raw", clientPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const sharedBits = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: clientKey }, serverPair.privateKey, 256));

  const prk = await hkdf(
    sharedBits, authSecret,
    new TextEncoder().encode("Content-Encoding: auth\0"), 32
  );

  const ctx = new Uint8Array([
    ...new TextEncoder().encode("P-256\0"),
    0, 65, ...clientPub,
    0, 65, ...serverPubRaw,
  ]);

  const cek   = await hkdf(prk, salt, new Uint8Array([...new TextEncoder().encode("Content-Encoding: aesgcm\0"), ...ctx]), 16);
  const nonce = await hkdf(prk, salt, new Uint8Array([...new TextEncoder().encode("Content-Encoding: nonce\0"),  ...ctx]), 12);

  const aesKey    = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const plaintext = new Uint8Array([0, 0, ...new TextEncoder().encode(payloadStr)]);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, plaintext));

  return {
    body: encrypted,
    headers: {
      "Content-Encoding": "aesgcm",
      "Encryption": `salt=${bytesToB64u(salt)}`,
      "Crypto-Key": `dh=${bytesToB64u(serverPubRaw)}`,
    },
  };
}

// ---- Envia para um endpoint ----
async function sendOne(sub, payloadStr, vapidHeader) {
  // Inscrição manual (sem SW real) — sem endpoint HTTP
  if (!sub.endpoint || !sub.endpoint.startsWith("http")) {
    return { ok: true, manual: true };
  }
  try {
    const { body, headers } = await encryptPayload(sub, payloadStr);
    const res = await fetch(sub.endpoint, {
      method: "POST",
      headers: {
        ...headers,
        "Authorization": vapidHeader,
        "Content-Type": "application/octet-stream",
        "TTL": "86400",
      },
      body,
    });
    // 410 = endpoint expirado (remover do banco futuramente)
    if (res.status === 410) return { ok: false, expired: true, status: 410 };
    return { ok: res.ok, status: res.status };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

// ---- Handler principal ----
serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  try {
    const PUB  = Deno.env.get("VAPID_PUBLIC_KEY")  ?? "";
    const PRIV = Deno.env.get("VAPID_PRIVATE_KEY") ?? "";
    const SUB  = Deno.env.get("VAPID_SUBJECT")     ?? "mailto:admin@ipdf.com";

    if (!PUB || !PRIV) {
      return new Response(JSON.stringify({ error: "VAPID_PUBLIC_KEY e VAPID_PRIVATE_KEY não configuradas nos secrets." }), {
        status: 500, headers: { ...CORS, "Content-Type": "application/json" },
      });
    }

    const body = await req.json();
    const { titulo, mensagem, tipo, icone, url, subscriptions = [] } = body;

    if (!subscriptions.length) {
      return new Response(JSON.stringify({ enviados: 0, erros: 0 }), {
        headers: { ...CORS, "Content-Type": "application/json" },
      });
    }

    const payloadStr = JSON.stringify({
      titulo:  titulo  ?? "IPDF",
      mensagem: mensagem ?? "",
      tipo:    tipo    ?? "geral",
      icone:   icone   ?? "/Logo-IPDF.png",
      url:     url     ?? "/",
    });

    let enviados = 0, erros = 0;
    const vapidCache = {};

    async function vapidFor(endpoint) {
      try {
        const { protocol, host } = new URL(endpoint);
        const aud = `${protocol}//${host}`;
        if (!vapidCache[aud]) {
          vapidCache[aud] = await makeVapidHeader(aud, SUB, PUB, PRIV);
        }
        return vapidCache[aud];
      } catch (e) {
        console.error("Erro ao gerar VAPID header:", e);
        return "";
      }
    }

    const BATCH = 50;
    for (let i = 0; i < subscriptions.length; i += BATCH) {
      await Promise.all(
        subscriptions.slice(i, i + BATCH).map(async (sub) => {
          try {
            const vh  = sub.endpoint?.startsWith("http") ? await vapidFor(sub.endpoint) : "";
            const res = await sendOne(sub, payloadStr, vh);
            if (res.ok) enviados++;
            else {
              console.error("Falha ao enviar:", sub.endpoint, res);
              erros++;
            }
          } catch (e) {
            console.error("Exceção ao enviar:", e);
            erros++;
          }
        })
      );
    }

    return new Response(JSON.stringify({ enviados, erros }), {
      headers: { ...CORS, "Content-Type": "application/json" },
    });

  } catch (e) {
    console.error("Erro geral:", e);
    return new Response(JSON.stringify({ error: String(e) }), {
      status: 500, headers: { ...CORS, "Content-Type": "application/json" },
    });
  }
});
