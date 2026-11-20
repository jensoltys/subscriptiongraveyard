// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
(function () {
  var APP = window.FEEDBACK_APP || document.title || 'Unknown';
  // Same-origin relay: the Worker rate-limits and forwards to FEEDBACK_WEBHOOK_URL.
  var ENDPOINT = '/api/feedback';

  var css = [
    '.fbw-btn{position:fixed;bottom:16px;right:16px;z-index:9998;background:#663399;color:#fff;border:0;border-radius:999px;padding:10px 18px;font:600 13px system-ui,-apple-system,sans-serif;cursor:pointer;box-shadow:0 2px 10px rgba(0,0,0,.18)}',
    '.fbw-btn:hover{background:#5a2d8a}',
    '.fbw-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:9999;display:none;align-items:center;justify-content:center;padding:16px}',
    '.fbw-overlay.fbw-open{display:flex}',
    '.fbw-modal{background:#fff;border-radius:14px;padding:24px;width:100%;max-width:460px;font:14px system-ui,-apple-system,sans-serif;color:#222;box-shadow:0 10px 40px rgba(0,0,0,.2);box-sizing:border-box;max-height:90vh;overflow-y:auto}',
    '.fbw-modal h3{margin:0 0 6px;font-size:18px;color:#222}',
    '.fbw-modal p.fbw-lede{margin:0 0 16px;color:#666;font-size:13px;line-height:1.4}',
    '.fbw-row{margin-bottom:14px}',
    '.fbw-row label.fbw-label{display:block;font-weight:600;margin-bottom:6px;font-size:13px;color:#333}',
    '.fbw-types{display:flex;gap:8px}',
    '.fbw-types label{flex:1;padding:8px;text-align:center;border:1px solid #ddd;border-radius:8px;cursor:pointer;font-weight:500;font-size:13px;user-select:none}',
    '.fbw-types input{position:absolute;opacity:0;pointer-events:none}',
    '.fbw-types label.fbw-on{border-color:#663399;background:#f4ebff;color:#663399}',
    '.fbw-modal textarea,.fbw-modal input[type=email]{width:100%;padding:9px 10px;border:1px solid #ddd;border-radius:6px;font:inherit;box-sizing:border-box;color:#222;background:#fff}',
    '.fbw-modal textarea{resize:vertical;min-height:90px}',
    '.fbw-modal textarea:focus,.fbw-modal input[type=email]:focus{outline:0;border-color:#663399;box-shadow:0 0 0 3px rgba(102,51,153,.15)}',
    '.fbw-modal small{color:#666;display:block;margin-top:4px;font-size:11px}',
    '.fbw-actions{display:flex;gap:8px;margin-top:18px}',
    '.fbw-actions button{flex:1;padding:11px;border:0;border-radius:6px;font:600 13px system-ui,-apple-system,sans-serif;cursor:pointer}',
    '.fbw-cancel{background:#eee;color:#333}',
    '.fbw-cancel:hover{background:#e0e0e0}',
    '.fbw-submit{background:#663399;color:#fff}',
    '.fbw-submit:hover{background:#5a2d8a}',
    '.fbw-submit:disabled{opacity:.5;cursor:default}',
    '.fbw-status{margin-top:12px;font-size:13px;padding:10px;border-radius:6px;display:none}',
    '.fbw-status.fbw-ok{background:#e9f9e9;color:#1e6b1e;display:block}',
    '.fbw-status.fbw-err{background:#fce8e8;color:#8a1a1a;display:block}'
  ].join('');
  var s = document.createElement('style');
  s.textContent = css;
  document.head.appendChild(s);

  function esc(x) {
    return String(x == null ? '' : x).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  var btn = document.createElement('button');
  btn.className = 'fbw-btn';
  btn.type = 'button';
  btn.textContent = 'Feedback';
  btn.setAttribute('aria-label', 'Report a bug or suggest a feature');
  document.body.appendChild(btn);

  var overlay = document.createElement('div');
  overlay.className = 'fbw-overlay';
  overlay.innerHTML =
    '<div class="fbw-modal" role="dialog" aria-label="Feedback form">' +
      '<h3>Report a bug or suggest a feature</h3>' +
      '<p class="fbw-lede">Your feedback shapes this app. Email is optional and only used if you want a follow-up. Never added to a mailing list.</p>' +
      '<form class="fbw-form" novalidate>' +
        '<div class="fbw-row">' +
          '<label class="fbw-label">Type</label>' +
          '<div class="fbw-types">' +
            '<label class="fbw-on"><input type="radio" name="type" value="bug" checked>Bug</label>' +
            '<label><input type="radio" name="type" value="feature">Feature idea</label>' +
            '<label><input type="radio" name="type" value="other">Other</label>' +
          '</div>' +
        '</div>' +
        '<div class="fbw-row">' +
          '<label class="fbw-label" for="fbw-msg">What\'s on your mind?</label>' +
          '<textarea id="fbw-msg" name="message" required maxlength="2000" placeholder="Describe what you saw, what you expected, or what you\'d like to see..."></textarea>' +
          '<small><span class="fbw-count">0</span> / 2000</small>' +
        '</div>' +
        '<div class="fbw-row">' +
          '<label class="fbw-label" for="fbw-email">Email (optional)</label>' +
          '<input type="email" id="fbw-email" name="email" maxlength="200" placeholder="you@example.com">' +
        '</div>' +
        '<div class="fbw-hp" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">' +
          '<label>Leave this empty<input type="text" name="website" tabindex="-1" autocomplete="off"></label>' +
        '</div>' +
        '<div class="fbw-actions">' +
          '<button type="button" class="fbw-cancel">Cancel</button>' +
          '<button type="submit" class="fbw-submit">Send</button>' +
        '</div>' +
        '<div class="fbw-status" role="status" aria-live="polite"></div>' +
      '</form>' +
    '</div>';
  document.body.appendChild(overlay);

  var form = overlay.querySelector('.fbw-form');
  var msgEl = overlay.querySelector('#fbw-msg');
  var countEl = overlay.querySelector('.fbw-count');
  var statusEl = overlay.querySelector('.fbw-status');
  var submitEl = overlay.querySelector('.fbw-submit');
  var modal = overlay.querySelector('.fbw-modal');

  msgEl.addEventListener('input', function () {
    countEl.textContent = String(msgEl.value.length);
  });

  Array.prototype.forEach.call(overlay.querySelectorAll('.fbw-types input'), function (input) {
    input.addEventListener('change', function () {
      Array.prototype.forEach.call(overlay.querySelectorAll('.fbw-types label'), function (l) {
        l.classList.toggle('fbw-on', l.contains(input) && input.checked);
      });
    });
  });

  // The form is an overlay, so it gets one history entry: Back closes it and
  // leaves the user on the app instead of leaving the site. The app's own
  // view state rides along so a refresh still lands on the same tab.
  btn.addEventListener('click', function () {
    try { history.pushState(Object.assign({}, history.state || {}, { fbw: 1 }), ''); } catch (e) { /* ignore */ }
    overlay.classList.add('fbw-open');
    setTimeout(function () { msgEl.focus(); }, 50);
  });
  overlay.querySelector('.fbw-cancel').addEventListener('click', function () { close(); });
  overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && overlay.classList.contains('fbw-open')) close();
  });
  window.addEventListener('popstate', function () {
    if (overlay.classList.contains('fbw-open') && !(history.state && history.state.fbw)) close(true);
  });

  function close(fromHistory) {
    if (!fromHistory && history.state && history.state.fbw) { history.back(); return; }
    overlay.classList.remove('fbw-open');
    form.reset();
    statusEl.className = 'fbw-status';
    statusEl.textContent = '';
    countEl.textContent = '0';
    submitEl.disabled = false;
    Array.prototype.forEach.call(overlay.querySelectorAll('.fbw-types label'), function (l, i) {
      l.classList.toggle('fbw-on', i === 0);
    });
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    var message = msgEl.value.trim();
    if (message.length < 3) {
      statusEl.className = 'fbw-status fbw-err';
      statusEl.textContent = 'Please write a bit more so I know what you mean.';
      return;
    }
    submitEl.disabled = true;
    statusEl.className = 'fbw-status';
    statusEl.textContent = '';
    var data = new FormData(form);
    var payload = {
      app: APP,
      type: String(data.get('type') || 'other'),
      message: message.slice(0, 2000),
      email: String(data.get('email') || '').trim().slice(0, 200),
      url: location.href.slice(0, 500),
      user_agent: (navigator.userAgent || '').slice(0, 500),
      website: String(data.get('website') || '')
    };
    try {
      var r = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (r.status === 429) {
        statusEl.className = 'fbw-status fbw-err';
        statusEl.textContent = "That's a lot of messages in a row. Try again in a few minutes.";
        submitEl.disabled = false;
        return;
      }
      if (!r.ok) { var j = await r.json().catch(function () { return null; }); throw new Error((j && j.error) || ''); }
      statusEl.className = 'fbw-status fbw-ok';
      statusEl.textContent = 'Got it. Thank you.';
      setTimeout(function () { close(); }, 2200);
    } catch (err) {
      statusEl.className = 'fbw-status fbw-err';
      statusEl.textContent = (err && err.message) || 'Could not send. Try again in a minute.';
      submitEl.disabled = false;
    }
  });
})();
