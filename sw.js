/* IPDF Church — Service Worker (coloque na raiz do repositório) */
const CACHE_NAME = 'ipdf-church-v1';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k=>k!==CACHE_NAME).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch(e) { data = { titulo:'IPDF Church', mensagem: event.data ? event.data.text() : 'Nova notificação.' }; }
  const titulo = data.titulo || 'IPDF Church';
  const mensagem = data.mensagem || '';
  const tipo = data.tipo || 'geral';
  const emoji = { devocional:'🙏', oracao:'💙', aviso:'📢', campanha:'🔥', geral:'✝️' }[tipo] || '✝️';
  event.waitUntil(self.registration.showNotification(titulo, {
    body: emoji + ' ' + mensagem, icon: data.icone || '/Logo-IPDF.png',
    badge: '/Logo-IPDF.png', tag: 'ipdf-' + tipo, renotify: true,
    vibrate: [200,100,200], data: { url: data.url || '/' },
    actions: [{ action:'open', title:'Abrir app' }, { action:'dismiss', title:'Dispensar' }]
  }));
});
self.addEventListener('notificationclick', event => {
  event.notification.close();
  if (event.action === 'dismiss') return;
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(clients.matchAll({ type:'window', includeUncontrolled:true }).then(ws => {
    for (const w of ws) if (w.url.includes(self.location.origin)) return w.focus().then(c => c.postMessage({ type:'NOTIF_CLICK', url }));
    return clients.openWindow(url);
  }));
});
self.addEventListener('pushsubscriptionchange', event => {
  event.waitUntil(clients.matchAll({ type:'window' }).then(cs => cs.forEach(c => c.postMessage({ type:'PUSH_SUBSCRIPTION_CHANGED' }))));
});
