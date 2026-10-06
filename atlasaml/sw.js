// Decrypts /atlasaml/app/<path> on the fly. Files live encrypted in enc/<sha256(path)[:40]>.bin
// (first 12 bytes = IV, rest = AES-256-GCM ciphertext). The key comes from the gate page via IndexedDB.
const BASE = new URL("./", self.location).pathname;          // "/atlasaml/"
const APP = BASE + "app/";
const TYPES = { html: "text/html; charset=utf-8", css: "text/css; charset=utf-8", js: "text/javascript; charset=utf-8",
  json: "application/json", txt: "text/plain; charset=utf-8", md: "text/plain; charset=utf-8", csv: "text/plain; charset=utf-8",
  pdf: "application/pdf", png: "image/png", jpg: "image/jpeg", svg: "image/svg+xml",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" };
let KEY = null;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("message", (e) => { if (e.data === "reset") KEY = null; });

function idbKey() {
  return new Promise((ok) => {
    const r = indexedDB.open("atlasaml", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("k");
    r.onerror = () => ok(null);
    r.onsuccess = () => { const g = r.result.transaction("k").objectStore("k").get("key"); g.onsuccess = () => ok(g.result || null); g.onerror = () => ok(null); };
  });
}

async function hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s.normalize("NFC")));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 40);
}

async function serve(req) {
  const url = new URL(req.url);
  KEY = KEY || (await idbKey());
  if (!KEY) return Response.redirect(BASE, 302);
  const path = decodeURIComponent(url.pathname.slice(APP.length));
  const r = await fetch(BASE + "enc/" + (await hex(path)) + ".bin", { cache: "no-cache" });
  if (!r.ok) return new Response("<meta charset=utf-8><p style='font:15px sans-serif;padding:24px'>Этого файла нет в опубликованной копии. <a href='" + BASE + "'>К началу</a></p>", { status: 404, headers: { "content-type": TYPES.html } });
  const b = new Uint8Array(await r.arrayBuffer());
  let plain;
  try { plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12) }, KEY, b.slice(12)); }
  catch { KEY = null; return Response.redirect(BASE, 302); }
  const ext = path.split(".").pop().toLowerCase();
  return new Response(plain, { headers: { "content-type": TYPES[ext] || "application/octet-stream", "cache-control": "no-store" } });
}

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin === self.location.origin && url.pathname.startsWith(APP)) e.respondWith(serve(e.request));
});
