/* ===========================================================
 *  binx / Dual Linkage Engine �?Service Worker
 *  Defense-in-depth supplement to in-page domain binding:
 *   1. Intercepts fetch before any page JS runs.
 *   2. Allows ONLY whitelisted deployment origins + sub-paths.
 *   3. Pin the SHA-256 of index.html to block file tampering.
 * =========================================================== */

// ---------- IMMUTABLE POLICY (hard-coded, not config) ----------
const POLICY = Object.freeze({
  // Whitelisted deployment prefixes (exact path segment matching)
  CANONICAL_PREFIXES: Object.freeze([
    'https://bnbclubone.github.io/bnix/',
    'https://bnbclubone.github.io/bnixclub/',
    'https://bnbclubone.github.io/cloud/',
    'https://bnixstaking.github.io/'
  ]),
  // If you rebuild index.html, regenerate via:
  //   $ cat index.html | openssl dgst -sha256 -binary | base64
  //   OR browser console:
  //   await crypto.subtle.digest('SHA-256', new TextEncoder().encode(htmlText))
  //     .then(b => btoa(String.fromCharCode(...new Uint8Array(b))))
  // Leave empty array to skip HTML hash pinning (only origin enforced).
  // ⚠️ 说明（2026-11-01）: 下面的 HTML 钉**只对根路径文档生效**（pathname 为 '/' 或
  //   '/index.html' / '/mainindex.html'，见 isMainDoc）。本项目的现网部署都在子路径
  //   （/bnix/、/bnixclub/、/cloud/），因此钉默认不参与校验；sub-app（/farm/）同理不受影响。
  //   若要给子路径也开启钉，需要同时放宽 isMainDoc，并把该路径下**所有**历史版本哈希入列，
  //   否则 CDN 缓存窗口内会有 403 风险。
  // 2026-11-01：连接卡死修复版（RPC 硬超时 + 健康通道排序 + 连接顺序调整）。
  //   数组第二项为修复前的旧哈希，用于缓存/回滚过渡；全网刷新后可只留第一项。
  PINNED_HTML_HASHES: Object.freeze([
    'CNUqe6HbT2RnIJ7DqIxQ410CZdFgqZ6iQ2x3U20Z2yU=', // 2026-11-01 连接卡死修复版
    'CgXT36n4N2hCljC9g6nQY9SCsTl7km5d3AcaUD6Kepc='  // 上一版（过渡用，可择期删除）
  ]),
  // How often to check for SW updates (seconds)
  UPDATE_CHECK_INTERVAL_SEC: 20
});

// ---------- Helpers (ES5, no import, no top-level await) ----------
function _segments(path) {
  return path.split('/').filter(function (s) { return s.length > 0; });
}

function _matchesPrefix(url, prefix) {
  if (url.indexOf(prefix) !== 0) return false;
  // Segment-level guard. E.g. "/cloudhacker/x" has prefix "/cloud/" in
  // raw string but first diff segment "cloudhacker" !== "cloud".
  var prefixPath = (function () {
    try { return new URL(prefix).pathname; } catch (_) { return '/'; }
  })();
  var reqPath = (function () { try { return new URL(url).pathname; } catch (_) { return '/'; } })();
  // Block path-traversal tricks (e.g. /cloud/../evil)
  if (reqPath.indexOf('..') !== -1) return false;
  var aSeg = _segments(prefixPath);
  var bSeg = _segments(reqPath);
  if (bSeg.length < aSeg.length) return false;
  for (var i = 0; i < aSeg.length; i++) {
    if (aSeg[i] !== bSeg[i]) return false;
  }
  return true;
}

function _isCanonicalUrl(url) {
  if (!url) return false;
  var prefixes = POLICY.CANONICAL_PREFIXES;
  for (var i = 0; i < prefixes.length; i++) {
    if (_matchesPrefix(url, prefixes[i])) return true;
  }
  return false;
}

async function _sha256Base64(textOrBytes) {
  var bytes;
  if (typeof textOrBytes === 'string') {
    bytes = new TextEncoder().encode(textOrBytes);
  } else {
    bytes = textOrBytes;
  }
  var hashBuf = await crypto.subtle.digest('SHA-256', bytes);
  var u8 = new Uint8Array(hashBuf);
  var bin = '';
  for (var i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

// Strip Cloudflare edge-injected beacon script (4everland adds this on every
// response; it must be removed before hashing so the pin stays stable).
function _stripEdgeInjections(html) {
  return html
    // <script type="module" src="https://static.cloudflareinsights.com/beacon.min.js/..." ...></script>
    .replace(/<script\b[^>]*static\.cloudflareinsights\.com\/beacon\.min\.js[^>]*><\/script>\r?\n?/gi, '')
    // any other cloudflareinsights script tag
    .replace(/<script\b[^>]*cloudflareinsights[^>]*><\/script>\r?\n?/gi, '');
}

// ---------- Install / Activate: take control immediately ----------
self.addEventListener('install', function (ev) {
  try { self.skipWaiting(); } catch (_) {}
});

self.addEventListener('activate', function (ev) {
  ev.waitUntil(Promise.resolve().then(function () {
    try { return self.clients.claim(); } catch (_) {}
  }));
});

// ---------- CORE: fetch interception BEFORE any in-page script ----------
self.addEventListener('fetch', function (ev) {
  var req = ev.request;
  var url = req.url;

  // Allow local debug origins: skip HTTPS + canonical prefix enforcement
  // so that http://localhost:8770 / http://127.0.0.1:8545 can be served.
  // NOTE: This bypass also skips HTML hash pinning for local origins, and
  // applies to every request (not only documents) so sub-app assets under
  // /farm/ can load during local testing.
  var localDebugRe = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/.*)?$/i;
  if (localDebugRe.test(url)) {
    // Let it pass without HTTPS, canonical prefix, or hash checks
    return;
  }

  // Pass through non-GET navigation-less (e.g. CORS preflight, POST RPC).
  if (req.method !== 'GET') return;

  // Reject non-HTTPS (block file://, blob:, data:, null origin for production).
  if (url.indexOf('https://') !== 0) {
    if (req.mode === 'navigate' || req.destination === 'document') {
      ev.respondWith(new Response(
        '<!doctype html><meta charset="utf-8"><title>blocked</title>' +
        '<body style="padding:40px;color:#b00;font:16px/1.6 sans-serif;text-align:center">' +
        '<b>INSECURE ORIGIN BLOCKED</b><br><br>' +
        'This dApp must be served over HTTPS from official paths.<br>' +
        'Current: <code>' + url + '</code>' +
        '</body></html>',
        { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
      ));
      return;
    }
    return;
  }

  // 1) CANONICAL ORIGIN + SUB-PATH ENFORCEMENT (segment-level)
  if (!_isCanonicalUrl(url)) {
    var prefixList = POLICY.CANONICAL_PREFIXES.join('<br>');
    ev.respondWith(new Response(
      '<!doctype html><meta charset="utf-8"><title>blocked</title>' +
      '<body style="padding:40px;color:#b00;font:16px/1.6 sans-serif;text-align:center">' +
      '<b>DEPLOYMENT PATH BLOCKED</b><br><br>' +
      'This dApp must be served from an official path:<br>' +
      '<code style="background:#f2f2f2;padding:2px 6px;border-radius:4px;display:block;margin:8px 0">' + prefixList + '</code><br>' +
      'Current: <code>' + url + '</code>' +
      '</body></html>',
      { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    ));
    return;
  }

  // 2) HTML INTEGRITY PIN (optional, MAIN DOCUMENT ONLY)
  //    This SW is registered at the site root (scope './'), so it also
  //    intercepts navigations to same-origin sub-apps such as /farm/.
  //    Pinning every navigation would 403 any sub-app whose HTML is not
  //    pinned, so the pin is narrowed to the root document.
  var isMainDoc = false;
  try {
    var _u = new URL(url);
    isMainDoc = (_u.pathname === '/' || /^\/(index|mainindex)\.html$/.test(_u.pathname));
  } catch (_) {}
  var isHtmlNav = (req.mode === 'navigate' || req.destination === 'document') && isMainDoc;

  if (isHtmlNav && POLICY.PINNED_HTML_HASHES.length > 0) {
    ev.respondWith((async function () {
      var resp = await fetch(req);
      if (!resp.ok) return resp;
      var clone = resp.clone();
      var txt = await clone.text();
      // Normalize edge injections (Cloudflare beacon) before hashing
      txt = _stripEdgeInjections(txt);
      var h = await _sha256Base64(txt);
      if (POLICY.PINNED_HTML_HASHES.indexOf(h) === -1) {
        return new Response(
          '<!doctype html><meta charset="utf-8"><title>tamper</title>' +
          '<body style="padding:40px;color:#b00;font:16px/1.6 sans-serif;text-align:center">' +
          '<b>HTML INTEGRITY CHECK FAILED</b><br><br>' +
          'The served main page does not match the pinned hash.<br>' +
          'Possible MITM / server tamper �?do not proceed.<br><br>' +
          'Got hash: <code>' + h + '</code>' +
          '</body></html>',
          { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
        );
      }
      return resp;
    })());
    return;
  }
});

// ---------- Periodic update check (best-effort) ----------
try {
  setInterval(function () {
    try { self.registration.update(); } catch (_) {}
  }, POLICY.UPDATE_CHECK_INTERVAL_SEC * 1000);
} catch (_) {}
