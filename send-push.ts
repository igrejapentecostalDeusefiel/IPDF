// @ts-nocheck
// Supabase Edge Function — send-push
// Secrets (Supabase → Settings → Edge Functions → Secrets):
//   VAPID_PUBLIC_KEY  = BEK2luLPeo_evRbHeBHI-BSU8aC8vAZmuzfJyv4hPKViBHNhN5W7l6oOGDczUpbX53Ve-WEqG9WLnyLyVoxMaAw
//   VAPID_PRIVATE_KEY = jQNChZgapcp9p2ikGlIZ2BgA-i_tu27Kf2Vy1PhANbY
//   VAPID_SUBJECT     = mailto:seu@email.com

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import * as webpush from "https://esm.sh/web-push@3.6.7";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  try {
    const PUB  = Deno.env.get("VAPID_PUBLIC_KEY")  ?? "";
    const PRIV = Deno.env.get("VAPID_PRIVATE_KEY") ?? "";
    const SUB  = Deno.env.get("VAPID_SUBJECT")     ?? "mailto:admin@ipdf.com";

    if (!PUB || !PRIV) {
      return new Response(
        JSON.stringify({ error: "VAPID keys não configuradas nos secrets." }),
        { status: 500, headers: { ...CORS, "Content-Type": "application/json" } }
      );
    }

    webpush.setVapidDetails(SUB, PUB, PRIV);

    const { titulo, mensagem, tipo, icone, url, subscriptions = [] } = await req.json();

    const payload = JSON.stringify({
      titulo:   titulo   ?? "IPDF",
      mensagem: mensagem ?? "",
      tipo:     tipo     ?? "geral",
      icone:    icone    ?? "/Logo-IPDF.png",
      url:      url      ?? "/",
    });

    let enviados = 0, erros = 0;

    await Promise.all(
      subscriptions.map(async (sub) => {
        // Endpoint manual (sem SW real) — não tem como entregar push
        if (!sub.endpoint || !sub.endpoint.startsWith("http")) {
          console.log("Endpoint manual ignorado:", sub.endpoint);
          erros++;
          return;
        }

        try {
          await webpush.sendNotification(
            { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
            payload,
            { TTL: 86400 }
          );
          enviados++;
        } catch (e) {
          console.error("Erro ao enviar para", sub.endpoint, "→", e.statusCode ?? e.message);
          // 410 = endpoint expirado (usuário desinstalou o browser/app)
          if (e.statusCode === 410 || e.statusCode === 404) {
            console.log("Endpoint expirado — deve ser removido do banco:", sub.endpoint);
          }
          erros++;
        }
      })
    );

    return new Response(
      JSON.stringify({ enviados, erros }),
      { headers: { ...CORS, "Content-Type": "application/json" } }
    );

  } catch (e) {
    console.error("Erro geral na Edge Function:", e);
    return new Response(
      JSON.stringify({ error: String(e) }),
      { status: 500, headers: { ...CORS, "Content-Type": "application/json" } }
    );
  }
});
