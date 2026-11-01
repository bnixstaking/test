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
  // ⚠️ 2026-09-28: 按需求方要求清空历史部署源，仅保留 fiststaking.github.io。
  //   避坑: 结尾斜杠不可省 —— _matchesPrefix 以 pathname 段级比对，根路径 '/' 表示
  //   该主机下任意路径放行（与历史 bnixstaking.github.io/ 同口径）。
  // 2026-11-01: 按要求重新加入 bnixstaking.github.io（根路径 ⇒ 该主机下任意后缀路径均放行）。
  CANONICAL_PREFIXES: Object.freeze([
    'https://fiststaking.github.io/',
    'https://bnixstaking.github.io/'
  ]),
  // If you rebuild index.html, regenerate via:
  //   $ cat index.html | openssl dgst -sha256 -binary | base64
  //   OR browser console:
  //   await crypto.subtle.digest('SHA-256', new TextEncoder().encode(htmlText))
  //     .then(b => btoa(String.fromCharCode(...new Uint8Array(b))))
  // Leave empty array to skip HTML hash pinning (only origin enforced).
  // 当前已回填第 ⑪ 代 index.html（核心地址第⑪代正式版 + 空投质押 0x1f4aC8D2…a506〔7 天周期〕
  // + OSK/FIST 质押 3 倍出局进度条 + 国库 convertFistdaoFeeToOskLp 任何人可调用按钮
  // 〔滑点固定 1500 bp〕+ 修正 1 FIST/1 OSK 兑换方向倒置 + 刷新频率改 60s
  // + 各 Tab 均设操作日志框（修复空投 Tab 操作无日志）+ 复投到期/授权前置校验
  // + 白名单 fiststaking.github.io + bnixstaking.github.io，2026-11-01）的 SHA-256
  // （base64，先剥离 Cloudflare beacon 注入）。
  // 2026-11-01 增补：Connect Wallet 卡死修复版（RPC 硬超时 + 健康通道排序 + 连接顺序调整）。
  // 数组里多留了一条「上一版」哈希，用于 GitHub Pages CDN（max-age=600）回源窗口内
  // 仍可能下发旧 index.html 的情况；等全网缓存刷新完（约 30 分钟后）可删掉第二项。
  // index.html 每次定稿后须重算此值，否则页面会被判为篡改并 403。
  PINNED_HTML_HASHES: Object.freeze([
    'nKvnBsW/GgRe+lqSoNOuSNVb4upJaQtra8jkS+Wd0Z4=', // 2026-11-01 连接卡死修复版
    '2YVRkS6GikWfH31dIfAE6tpCiGuDHkVxqXUW+qUcvl4='  // 上一版（CDN 缓存窗口过渡用，可择期删除）
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
  // NOTE: This bypass also skips HTML hash pinning for local origins.
  if (req.mode === 'navigate' || req.destination === 'document') {
    var localDebugRe = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/.*)?$/i;
    if (localDebugRe.test(url)) {
      // Let it pass without HTTPS, canonical prefix, or hash checks
      return;
    }
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
  //    WARNING: this SW is registered at the site root (scope './'), so it also
  //    intercepts navigations to sub-apps such as /farm/. Pinning every
  //    navigation would 403 any sub-app whose HTML is not pinned, so the pin is
  //    narrowed to the root document ( "/" or "/index.html" or "/mainindex.html" ).
  //    Byte-level note: this block is ASCII-only on purpose -- sw.js contains two
  //    invalid UTF-8 bytes elsewhere; never rewrite this file through a text editor.
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
