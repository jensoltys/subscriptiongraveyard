// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// Email look: "App header" layout.
// A header band like the top of the app (app name, title, optional kicker on
// the left, the app's mascot on the right), an accent rule, then the body card
// on the app's dark background. The THEME object
// the worker passes in sets the colors and mascot.
//
// Email-client rules this follows: table layout + inline styles (Outlook), a
// bgcolor fallback under every gradient, plain 6-digit hex only (no alpha hex),
// and web fonts listed first with safe fallbacks (Gmail strips web fonts).
//
// THEME shape: { name, mascotUrl, mascotAlt, mascotW, bg, card, line, pri, pri2, on, a2, text, muted }
// mascotW = the mascot PNG's width when shown 100px tall.

export const FONT_DISPLAY = "'Bricolage Grotesque','Trebuchet MS',Arial,sans-serif";
export const FONT_BODY = "Figtree,'Segoe UI',Helvetica,Arial,sans-serif";

function mixHex(hex, target, pct) {
  const a = parseInt(hex.slice(1), 16), b = parseInt(target.slice(1), 16);
  const ch = (s) => {
    const x = (a >> s) & 255, y = (b >> s) & 255;
    return Math.round(x + (y - x) * pct).toString(16).padStart(2, '0');
  };
  return '#' + ch(16) + ch(8) + ch(0);
}

export function emailPara(t, html) {
  return `<p style="margin:0 0 6px;font-family:${FONT_BODY};font-size:15px;line-height:1.6;color:${t.text}">${html}</p>`;
}

export function emailSmall(t, html, align = 'center') {
  return `<p style="margin:16px 0 0;font-family:${FONT_BODY};font-size:13px;line-height:1.6;color:${t.muted};text-align:${align}">${html}</p>`;
}

export function emailCode(t, code) {
  return `<div style="margin:18px 0;padding:18px 10px;text-align:center;background:${t.bg};border:1px solid ${t.line};border-radius:14px"><span style="font-family:${FONT_DISPLAY};font-size:38px;font-weight:800;letter-spacing:10px;color:${t.pri}">${code}</span></div>`;
}

export function emailBigStat(t, value, label) {
  return `<div style="margin:0 0 16px;padding:20px 14px;text-align:center;background:${t.bg};border:1px solid ${t.line};border-radius:14px"><div style="font-family:${FONT_DISPLAY};font-size:40px;line-height:1.1;font-weight:800;color:${t.a2}">${value}</div><div style="font-family:${FONT_BODY};font-size:14px;color:${t.muted};margin-top:6px">${label}</div></div>`;
}

export function emailLabel(t, txt) {
  return `<div style="font-family:${FONT_DISPLAY};font-size:12px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase;color:${t.pri};margin:20px 0 2px">${txt}</div>`;
}

// rows: [[label, value], ...] (both already HTML-escaped by the caller)
export function emailRows(t, rows) {
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;border-collapse:collapse;margin:4px 0">${rows.map(([l, v]) =>
    `<tr><td style="padding:10px 0;font-family:${FONT_BODY};color:${t.muted};font-size:15px;border-bottom:1px solid ${t.line}">${l}</td><td style="padding:10px 0 10px 12px;text-align:right;font-family:${FONT_BODY};color:${t.text};font-size:15px;font-weight:700;border-bottom:1px solid ${t.line}">${v}</td></tr>`).join('')}</table>`;
}

export function emailButton(t, href, label) {
  return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center" style="margin:24px auto 4px"><tr><td bgcolor="${t.pri}" style="border-radius:12px;background:${t.pri};background:linear-gradient(135deg,${t.pri} 0%,${t.pri2} 100%)"><a href="${href}" style="display:inline-block;padding:14px 30px;font-family:${FONT_DISPLAY};font-size:16px;font-weight:800;color:${t.on};text-decoration:none;border-radius:12px">${label}</a></td></tr></table>`;
}

// The full email. body = HTML built from the helpers above. footer = the app's
// uniform footer HTML (emailFooterHtml), plus anything that must sit above it.
export function emailLayout(t, { title, kicker = '', body, footer = '', preheader = '' }) {
  return emailOpen(t, preheader) + emailHeader(t, title, kicker) + body + emailClose(t, footer);
}

// The same layout in three pieces, for callers that build header and body
// separately (the hub's recap renderers).
export function emailOpen(t, preheader = '') {
  return `${preheader ? `<div style="display:none;max-height:0;overflow:hidden;mso-hide:all">${preheader}</div>` : ''}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${t.bg}" style="width:100%;background:${t.bg}"><tr><td align="center" style="padding:22px 12px 4px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:560px">
<tr><td bgcolor="${t.card}" style="background:${t.card};border:1px solid ${t.line};border-radius:20px;overflow:hidden;padding:0">`;
}

export function emailHeader(t, title, kicker = '') {
  const glow = mixHex(t.card, t.pri, 0.22);
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${t.card}" style="width:100%;background:${t.card};background:linear-gradient(135deg,${t.bg} 0%,${t.card} 55%,${glow} 100%)"><tr>
<td style="padding:22px 8px 18px 24px;vertical-align:bottom">
<div style="font-family:${FONT_DISPLAY};font-size:12px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:${t.pri}">${t.name}</div>
<div style="font-family:${FONT_DISPLAY};font-size:26px;line-height:1.15;font-weight:800;color:${t.text};margin:6px 0 4px">${title}</div>
${kicker ? `<div style="font-family:${FONT_BODY};font-size:14px;color:${t.muted}">${kicker}</div>` : ''}
</td>
<td width="110" align="right" style="width:110px;padding:14px 18px 0 0;vertical-align:bottom"><img src="${t.mascotUrl}" alt="${t.mascotAlt}" width="${t.mascotW || 84}" height="100" style="display:block;width:${t.mascotW || 84}px;height:100px;border:0"></td>
</tr></table>
<div style="height:3px;line-height:3px;font-size:0;background:${t.pri};background:linear-gradient(90deg,${t.pri},${t.a2})">&nbsp;</div>
<div style="padding:22px 24px 24px">`;
}

export function emailClose(t, footer = '') {
  return `</div>
</td></tr></table>
</td></tr>
<tr><td align="center" style="padding:0 20px 22px"><div style="max-width:560px;margin:0 auto;font-family:${FONT_BODY}">${footer}</div></td></tr>
</table>`;
}
