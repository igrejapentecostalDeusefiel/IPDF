/* =========================================================
   IPDF CHURCH — Service Worker
   Responsável por:
   1. Receber e exibir Web Push Notifications (push event)
   2. Tratar cliques nas notificações (notificationclick)
   3. Cache offline básico (install/activate)
   ========================================================= */

const CACHE_NAME = 'ipdf-church-v1';

// ---- Install: registra o SW sem pré-cachear nada pesado ----
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

// ---- Activate: assume controle imediatamente ----
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// ---- Push: recebe a notificação e a exibe ----
self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { titulo: 'IPDF Church', mensagem: event.data ? event.data.text() : 'Nova notificação.' };
  }

  const titulo   = data.titulo   || 'IPDF Church';
  const mensagem = data.mensagem || '';
  const icone    = data.icone    || '/Logo-IPDF.png';
  const badge    = data.badge    || '/Logo-IPDF.png';
  const url      = data.url      || '/IPDF/';
  const tipo     = data.tipo     || 'geral';

  // Emoji de tipo para o corpo
  const emojiTipo = {
    devocional: '🙏',
    oracao:     '💙',
    aviso:      '📢',
    campanha:   '🔥',
    geral:      '✝️',
  }[tipo] || '✝️';

  const options = {
    body:    `${emojiTipo} ${mensagem}`,
    icon:    icone,
    badge:   badge,
    tag:     `ipdf-${tipo}`,            // agrupa por tipo (substitui em vez de empilhar)
    renotify: true,
    vibrate: [200, 100, 200],
    data:    { url },
    actions: [
      { action: 'open',    title: 'Abrir app' },
      { action: 'dismiss', title: 'Dispensar'  },
    ],
  };

  event.waitUntil(
    self.registration.showNotification(titulo, options)
  );
});

// ---- Clique na notificação ----
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  if (event.action === 'dismiss') return;

  const targetUrl = (event.notification.data && event.notification.data.url) || '/IPDF/';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      // Se já tem uma aba/janela aberta, foca nela
      for (const client of windowClients) {
        if (client.url === targetUrl || client.url.includes(self.location.origin)) {
          return client.focus().then(c => c.postMessage({ type: 'NOTIF_CLICK', url: targetUrl }));
        }
      }
      // Senão, abre uma nova janela
      return clients.openWindow(targetUrl.includes(self.location.origin) ? targetUrl : self.location.origin + '/IPDF/');
    })
  );
});

// ---- Push subscription change (renovação automática) ----
self.addEventListener('pushsubscriptionchange', (event) => {
  // Notifica a página para re-registrar a inscrição
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then(cs => {
      cs.forEach(c => c.postMessage({ type: 'PUSH_SUBSCRIPTION_CHANGED' }));
    })
  );
});
