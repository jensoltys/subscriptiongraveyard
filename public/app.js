// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
'use strict';

// The tab (or day) the user was on before they hit refresh. history.state
// survives a reload of the same entry, but init() replaceState()s an
// auth-landing entry over it before enterApp() ever runs — and the hub-handoff
// replaceState above can too — so it has to be captured HERE, at module load,
// before anything touches history. Without it, refreshing anywhere but the
// default tab bounced the user back to the default.
const BOOT_VIEW=(history.state||{}).view||null;
// Same idea for the logged-out screen: a refresh on the log-in or sign-up card
// stays there, and a refresh on the guest sample stays on the guest sample.
const BOOT_AUTH=(history.state||{}).authView||null;
const BOOT_GUEST=(history.state||{}).guestView||null;

// Cross-app Pro handoff from app-hub
let HUB_ARRIVAL=false;
(function captureHubPro() {
  const qs = new URLSearchParams(location.search);
  const hubpro = qs.get('hubpro');
  if (hubpro) {
    // A fresh hubpro in the URL means the user just arrived via the hub and may
    // be a different identity than whoever was last logged in here. Drop the
    // local session so the bootstrap path will re-run hub-sso against the new
    // JWT instead of silently keeping the previous user signed in. The session
    // is an HttpOnly cookie now, so "drop" means: skip the /api/me check and
    // let hub-sso replace the cookie. Any pre-cookie localStorage token goes too.
    HUB_ARRIVAL = true;
    try { localStorage.removeItem('sg_token'); } catch (e) {}
    localStorage.setItem('hub_pro_jwt', hubpro);
    qs.delete('hubpro');
    const newQs = qs.toString();
    history.replaceState({}, '', location.pathname + (newQs ? '?' + newQs : ''));
  }
})();

// ===== BOOT GATE =====
// #auth-screen is hidden in the markup, so the logged-out card cannot paint over
// a session that is seconds from resolving. Arriving from the hub with ?hubpro=
// used to show the Log In / Sign Up tabs, the email field and the password field
// for about half a second while hub-sso ran, on the one journey whose whole
// promise is that you never see a second sign-in.
// The call is made here, synchronously, before any network request.
function showAuthScreen(){
  const boot=document.getElementById('boot-screen');
  if(boot)boot.style.display='none';
  const auth=document.getElementById('auth-screen');
  if(auth)auth.style.display='flex';
}
function hideBootScreen(){
  const boot=document.getElementById('boot-screen');
  if(boot)boot.style.display='none';
}
// The session is an HttpOnly cookie the page can't read, so the boot screen
// stays up until init() asks GET /api/me (401 = show the login card). A
// logged-in user never sees the login card flash, and a logged-out one sees
// the boot screen for one round trip.
(function bootGate(){
  const msg=document.getElementById('boot-msg');
  if(msg)msg.textContent=HUB_ARRIVAL?'Signing you in from the hub…':'Opening your graveyard…';
})();

// ===== HUB PRO TOKEN REFRESH =====
// The hub JWT in localStorage expires. Instead of silently demoting a Pro user
// to free, refresh it on demand through our worker proxy (which relays to
// app-hub). Called on init when the stored token is expired/near expiry, and
// once per pro-rejected API response. Never polled.
const PRO_PAUSED_MSG='pro paused? open your app hub and relaunch to refresh.';
let proPaused=false; // true when a previously-Pro token could not be refreshed
function decodeHubJwt(tok){
  try{
    const p=tok.split('.')[1].replace(/-/g,'+').replace(/_/g,'/');
    return JSON.parse(atob(p+'='.repeat((4-p.length%4)%4)));
  }catch(e){return null;}
}
function hubTokenExpiringSoon(tok){
  const payload=decodeHubJwt(tok);
  if(!payload||typeof payload.exp!=='number')return true;
  return payload.exp<(Date.now()/1000)+60;
}
function hubTokenHasPro(tok){
  const payload=decodeHubJwt(tok);
  return !!(payload&&payload.pro_until);
}
let _hubRefreshPromise=null;
// Resolves true (fresh token stored), false (hub says invalid — token removed,
// user is free), or null (hub unreachable / rate-limited — keep current state).
function refreshHubPro(){
  if(_hubRefreshPromise)return _hubRefreshPromise;
  const stored=localStorage.getItem('hub_pro_jwt');
  if(!stored)return Promise.resolve(false);
  _hubRefreshPromise=(async()=>{
    try{
      const r=await fetch('/api/pro-refresh',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:stored})});
      const data=await r.json().catch(()=>null);
      if(data&&data.valid===true&&typeof data.token==='string'){localStorage.setItem('hub_pro_jwt',data.token);proPaused=false;return true;}
      if(data&&data.valid===false){localStorage.removeItem('hub_pro_jwt');return false;}
      return null;
    }catch(e){return null;}
  })();
  const p=_hubRefreshPromise;
  p.finally(()=>{_hubRefreshPromise=null;});
  return p;
}
function showProPaused(){proPaused=true;showToast(PRO_PAUSED_MSG);}

// ===== OVERLAY HISTORY =====
// Fleet back-button rule: opening an overlay is a move-in, so it gets its own
// history entry. Without this, a free user who hits the Pro gate and presses
// Back leaves the site entirely (the modal isn't a history entry, so Back pops
// whatever was underneath the whole app).
//
// The contract:
//   - pushOverlayState() on open.
//   - Every close function takes a `fromHistory` flag. When it's falsy the
//     close routes through history.back() and lets popstate do the hiding, so
//     the on-screen button and the browser button stay in sync — otherwise the
//     button hides the modal and the stale entry eats the next Back press.
//   - closeAllOverlays() (called BY popstate) passes fromHistory=true, or
//     popstate would re-enter history.back() and loop.
// `view`/`authView` are spread through so closing an overlay still restores the
// tab underneath it.
let overlayDepth = 0;
function pushOverlayState() {
  history.pushState({ ...history.state, sgOverlay: ++overlayDepth }, '', location.href);
}
// Consumes the overlay's history entry if it has one. Returns true when
// history.back() was called, meaning popstate will finish the close.
// Guarded on sgOverlay so an overlay opened by some path that skipped
// pushOverlayState() can never send a Back press out of the app.
function popOverlayState() {
  if (history.state && history.state.sgOverlay) { history.back(); return true; }
  return false;
}

// ===== UNIFIED PRO-REQUIRED MODAL =====
// Triggered by any 402 from API or by
// client-side pre-gates that want to show the upgrade prompt directly.
const PRO_FROM = 'graveyard';
const PRO_FEATURE_COPY = {
  'unlimited-burials': { title: 'Unlimited burials', desc: 'Free includes 5 canceled subscriptions. Pro removes the cap.' },
  'unlimited-death-row': { title: 'Unlimited Last Rites', desc: 'Free includes 5 Last Rites items. Pro removes the cap.' },
  'renewal-watchlist': { title: 'Renewal warnings', desc: 'Get email warnings before subscriptions auto-renew so you can cancel in time.' },
};
function showProRequired(feature) {
  let copy = PRO_FEATURE_COPY[feature] || { title: 'Pro feature', desc: 'This is part of Pro.' };
  // Previously-Pro user whose hub token could not refresh: the keeper explains.
  if (proPaused) copy = { title: copy.title, desc: PRO_PAUSED_MSG };
  // This copy has no Pro hub: Pro only exists on the hosted version, so say that plainly.
  if (!proAvailable) copy = { title: copy.title, desc: "Pro isn't available on this copy of Subscription Graveyard. It's part of the hosted version at subscriptiongraveyard.app. A graveyard there starts fresh, nothing moves over from here." };
  const url = !proAvailable ? 'https://subscriptiongraveyard.app' : !proUpgradeUrl ? '#' : proUpgradeUrl + (feature ? (proUpgradeUrl.includes('?') ? '&' : '?') + 'feature=' + encodeURIComponent(feature) : '');
  const modal = document.getElementById('pro-required-modal');
  if (!modal) return;
  modal.querySelector('#pro-required-title').textContent = copy.title;
  modal.querySelector('#pro-required-desc').textContent = copy.desc;
  const cta = modal.querySelector('#pro-required-cta');
  cta.href = url;
  cta.textContent = proAvailable ? 'Go Pro' : 'Open subscriptiongraveyard.app';
  cta.hidden = proAvailable && !proUpgradeUrl;
  pushOverlayState();
  modal.style.display = 'flex';
}
function closeProRequired(fromHistory) {
  if (!fromHistory && popOverlayState()) return;
  const m = document.getElementById('pro-required-modal');
  if (m) m.style.display = 'none';
}
document.addEventListener('click', (e) => {
  if (e.target?.dataset?.action === 'close-pro-modal') closeProRequired();
});

// ===== CONFIG =====
const CATEGORIES=[{value:'streaming',label:'Streaming'},{value:'software',label:'Software/SaaS'},{value:'fitness',label:'Fitness/Wellness'},{value:'food',label:'Food Delivery'},{value:'news',label:'News/Media'},{value:'gaming',label:'Gaming'},{value:'music',label:'Music'},{value:'audiobooks',label:'Audiobooks/Reading'},{value:'storage',label:'Cloud Storage'},{value:'productivity',label:'Productivity'},{value:'other',label:'Other'}];
const PARTICLE_COLORS=['#6EDBA8','#FF6B57','#E9DFC9','#F2B45A','#A6EDCB','#FF9A8A'];
// ---------------------------------------------------------------------------
// TIPS and NUDGES are deliberately SEPARATE. Help with the app
// is not a promo and must never take a promo's slot, or the promo surface just
// isn't one that day. TIPS teach the app. NUDGES sell something.
// ---------------------------------------------------------------------------
// App help. Rotates daily in #app-tip, above the promo card. No links, no
// labels, nothing to disclose. `act` runs a small in-app action.
const TIPS=[
  {text:'Every tombstone keeps earning on its own. A sub buried three months ago has already saved you three months of its price.',cta:'Open the graveyard',act:'go-graveyard'},
  {text:'Canceled something last year? Bury it with the real date and it counts everything it has saved you since.',cta:'Bury one',act:'go-bury'},
  {text:'Last Rites is for the ones you keep meaning to cancel. Parking them there is how they stop being invisible.',cta:'Open Last Rites',act:'go-deathrow'},
  {text:'Your rank comes from monthly savings, not how many you buried. One expensive cancellation moves it more than five cheap ones.',cta:'See my stats',act:'go-stats'},
  {text:'Adding the start date when you bury something shows what that subscription cost you over its whole life.',cta:'Bury one',act:'go-bury'},
  {text:'The Crypt Keeper has opinions. Click him when you need a push.',cta:'Poke the Keeper',act:'poke-keeper'},
  {text:'Everything in the app is explained in one place, with pictures.',cta:'Open how it works',act:'open-help'},
];
function renderAppTip(){
  const slot=document.getElementById('app-tip');
  if(!slot)return;
  const doy=Math.floor((Date.now()-new Date(new Date().getFullYear(),0,0))/86400000);
  const t=TIPS[doy%TIPS.length];
  slot.innerHTML=`<div class="tip-card help-tip"><div class="tip-text">${esc(t.text)}</div>`+
    `<button type="button" class="tip-cta" data-action="tip-act" data-tip-act="${esc(t.act)}">${esc(t.cta)} &rarr;</button></div>`;
}
// The CTA on an app-help tip. Never navigates off-site; that is what a promo does.
function runTipAction(act){
  switch(act){
    case 'go-graveyard': goTab('graveyard'); break;
    case 'go-bury':      goTab('add'); break;
    case 'go-deathrow':  goTab('deathrow'); break;
    case 'go-stats':     goTab('dashboard'); break;
    case 'poke-keeper':  {const k=document.querySelector('.character-wrap'); if(k){k.scrollIntoView({block:'center',behavior:'smooth'});k.click();} break;}
    case 'open-help':    openHelp(); break;
  }
}

// Promos only: Jen Built It's own apps and posts. Swap in your own.
const GENERAL_NUDGES=[{text:'You\'re saving money by canceling subs. See how close your side income is to covering your bills.',link:'https://sidehustlegarden.com/',cta:'Try Side Hustle Garden'},{text:'Track your energy throughout the day. Find what charges and drains you.',link:'https://energybattery.app',cta:'Try Energy Battery'},{text:'All that money you\'re saving? Redirect it to an emergency fund and watch sea creatures come alive.',link:'https://emergencyfundaquarium.com',cta:'Try Emergency Fund Aquarium'},{text:'Make canceling subscriptions a daily habit. Build streaks with Dopamine Dealer.',link:'https://dopaminedealerhabits.com/',cta:'Try Dopamine Dealer'},{text:'All that money you\'re saving? Track where it goes. Watch your bills shrink as your side hustle grows.',link:'https://sidehustlegarden.com/',cta:'Track with Side Hustle Garden'},{text:'Buried everything you know about? Jen Built It, the app\'s maker, listed the 7 places subscriptions hide, with a free printable tracker.',link:'https://adminarcade.com/free-printable-subscription-tracker/',cta:'Find the hidden ones'},{text:'Before you cancel, check what your subs already include. Jen Built It, the app\'s maker, keeps a free database of the perks hiding inside the plans you pay for.',link:'https://seedingserendipity.com/subscription-perks/',cta:'Search the perks'},{text:'Not sure what to keep? Audit every subscription in 10 minutes with the keep, audit, cancel method.',link:'https://seedingserendipity.com/how-to-audit-subscriptions/',cta:'Read: audit your subs'},{text:'Paying monthly for a link in bio? Jen Built It, the app\'s maker, built one with a free plan you can use instead.',link:'https://buildabio.com',cta:'Try Build a Bio'},{text:'Paying for a giveaway app? Jen Built It, the app\'s maker, built one that embeds on any blog with a line of HTML.',link:'https://giveawaywidget.com',cta:'Try Giveaway Widget'},{text:'Cutting subscriptions frees up cash. Raising what you earn is the other lever, and that starts with a resume that actually gets read.',link:'https://resumeprune.com/',cta:'Try Resume Prune'},{text:'Jen, the app\'s maker, canceled a pile of software subscriptions by building her own replacements. Here\'s what went and what she uses now.',link:'https://jen8n.com/software-subscriptions-i-cancelled/',cta:'Read: what she canceled'}];
const CATEGORY_NUDGES={fitness:[{text:'Canceled a fitness sub? Build exercise habits for free with Dopamine Dealer.',link:'https://dopaminedealerhabits.com/',cta:'Build free fitness habits'}]};
function isAff(url){if(!url)return false;const own=['dopaminedealerhabits.com','sidehustlegarden.com','subscriptiongraveyard.app','emergencyfundaquarium.com','energybattery.app','jen8ndirectory.com','resumeprune.com','jenbuiltit.com','jen8n.com','seedingserendipity.com','jentriedit.com','buildabio.com','giveawaywidget.com','porchpile.com','adminarcade.com','recipecolumncards.com','questmytasks.com'];return !own.some(d=>url.includes(d));}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
const TIERS=[{key:'reaper',label:'Grim Reaper',min:500},{key:'undertaker',label:'Undertaker',min:200},{key:'gravedigger',label:'Gravedigger',min:100},{key:'mourner',label:'Mourner',min:50},{key:'ghost',label:'Ghost',min:0}];
const MILESTONES=[{key:'first-kill',threshold:0,check:s=>s.length===1,title:'FIRST BURIAL!',msg:'You buried your first subscription. The graveyard has begun.'},{key:'saved-100',threshold:100,title:'$100 SAVED!',msg:'Your graveyard saved you over $100. The buried subscriptions salute you.'},{key:'saved-500',threshold:500,title:'$500 SAVED!',msg:'Half a grand from burying subscriptions. You\'re a one-person cemetery.'},{key:'saved-1000',threshold:1000,title:'$1,000 SAVED!',msg:'One thousand dollars saved. Your wallet is dancing.'},{key:'saved-5000',threshold:5000,title:'$5,000 SAVED!',msg:'FIVE THOUSAND DOLLARS. You are the Grim Reaper of subscriptions.'}];
const CELEB_MSGS={reaper:[{title:'THE REAPER STRIKES!',msg:'Another soul claimed. Your savings are legendary.'},{title:'BURIED WITH HONORS',msg:'This subscription never stood a chance.'}],undertaker:[{title:'ANOTHER ONE BURIED!',msg:'Six feet under. Your wallet is grateful.'},{title:'REST IN SAVINGS',msg:'Officially six feet under.'}],gravedigger:[{title:'GRAVE DUG!',msg:'Another sub bites the dust. Keep digging!'},{title:'DIG DEEPER',msg:'Your graveyard grows. Savings grow faster.'}],mourner:[{title:'A MOMENT OF SILENCE...',msg:'For the subscription that drained your wallet. RIP.'},{title:'GONE BUT NOT MISSED',msg:'Your bank account certainly won\'t miss it.'}],ghost:[{title:'SUBSCRIPTION CANCELED!',msg:'This ghost won\'t haunt your wallet anymore.'},{title:'MONEY SAVED!',msg:'Every canceled subscription is a small victory.'}]};

// Graveyard Creatures (SVG). Blood Moon set. One style: rounded shapes, 1.8px dark ink
// outline, big glossy eyes. The sticker border + glow come from CSS on .celeb-creature svg.
const CR_INK='#1A1416';
const crEye=(cx,cy,r,iris)=>`<circle cx="${cx}" cy="${cy}" r="${r}" fill="#fff" stroke="${CR_INK}" stroke-width="1.8"/><circle cx="${cx+.6}" cy="${cy+.8}" r="${r*.62}" fill="${iris}"/><circle cx="${cx+.6}" cy="${cy+.8}" r="${r*.3}" fill="${CR_INK}"/><circle cx="${cx-r*.3}" cy="${cy-r*.35}" r="${r*.26}" fill="#fff"/>`;
const CREATURES={
  ghost:`<svg viewBox="0 0 100 100" width="100" height="100"><path d="M23 52Q12 51 13 40Q20 43 24 46Z" fill="#EEE6DC" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M77 52Q88 51 87 40Q80 43 76 46Z" fill="#EEE6DC" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M22 88V46C22 26 34 13 50 13S78 26 78 46V88L70 81 62 88 54 81 46 88 38 81 30 88Z" fill="#EEE6DC" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M66 20C74 26 78 35 78 46V88L70 81 62 88V40C62 32 65 26 66 20Z" fill="#D7CDC8" opacity=".7"/><ellipse cx="37" cy="25" rx="6" ry="3.5" fill="#fff" opacity=".7" transform="rotate(-25 37 25)"/><ellipse cx="40" cy="45" rx="6" ry="8" fill="${CR_INK}"/><ellipse cx="60" cy="45" rx="6" ry="8" fill="${CR_INK}"/><circle cx="38" cy="42" r="2.3" fill="#fff"/><circle cx="58" cy="42" r="2.3" fill="#fff"/><ellipse cx="50" cy="60" rx="3.6" ry="4.6" fill="${CR_INK}"/><ellipse cx="31" cy="55" rx="4.5" ry="2.6" fill="#FF6B57" opacity=".45"/><ellipse cx="69" cy="55" rx="4.5" ry="2.6" fill="#FF6B57" opacity=".45"/></svg>`,
  bat:`<svg viewBox="0 0 100 100" width="100" height="100"><path d="M44 46C34 30 16 26 6 36c6 2 8 8 8 14 4-4 10-3 12 2 4-4 10-3 12 2 2-4 4-4 6-2z" fill="#4A3235" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M56 46c10-16 28-20 38-10-6 2-8 8-8 14-4-4-10-3-12 2-4-4-10-3-12 2-2-4-4-4-6-2z" fill="#4A3235" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M14 50c7-7 17-9 28-6M86 50c-7-7-17-9-28-6M26 52c4-5 9-7 15-7M74 52c-4-5-9-7-15-7" stroke="#7A4F53" stroke-width="1.4" fill="none" stroke-linecap="round"/><path d="M40 38l1-16 8 11zM60 38l-1-16-8 11z" fill="#6B4549" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M42 33l.6-6 3 4zM58 33l-.6-6-3 4z" fill="#FF6B57" opacity=".7"/><ellipse cx="50" cy="49" rx="13" ry="14" fill="#6B4549" stroke="${CR_INK}" stroke-width="1.8"/><ellipse cx="50" cy="56" rx="7.5" ry="6.5" fill="#8A5358"/>${crEye(44.5,46,5,'#FF6B57')}${crEye(55.5,46,5,'#FF6B57')}<path d="M45 55q5 4 10 0" stroke="${CR_INK}" stroke-width="1.6" fill="none" stroke-linecap="round"/><path d="M46.3 55.6l1.1 3 1.3-2.6zM51.3 56l1.3 2.6 1.1-3z" fill="#fff" stroke="${CR_INK}" stroke-width=".8" stroke-linejoin="round"/></svg>`,
  raven:`<svg viewBox="0 0 100 100" width="100" height="100"><path d="M44 81v8m0 0l-4 3m4-3l4 3M56 81v8m0 0l-4 3m4-3l4 3" stroke="#F2B45A" stroke-width="2.6" stroke-linecap="round" fill="none"/><path d="M46 31l-3-10 7 6 4-9v12z" fill="#3B3140" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><ellipse cx="50" cy="56" rx="23" ry="27" fill="#3B3140" stroke="${CR_INK}" stroke-width="1.8"/><ellipse cx="50" cy="69" rx="11" ry="12" fill="#4F4458"/><path d="M29 50c-7 12-4 27 8 32-2-12-2-22 3-30z" fill="#52465A" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M71 50c7 12 4 27-8 32 2-12 2-22-3-30z" fill="#52465A" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><ellipse cx="42" cy="40" rx="5" ry="2.5" fill="#fff" opacity=".18"/>${crEye(42,49,7,'#F2B45A')}${crEye(58,49,7,'#F2B45A')}<path d="M45 57h10l-5 9z" fill="#F2B45A" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M36 42l9 3M64 42l-9 3" stroke="${CR_INK}" stroke-width="2.2" stroke-linecap="round"/></svg>`,
  cat:`<svg viewBox="0 0 100 100" width="100" height="100"><path d="M68 86c16 0 21-14 13-24" stroke="${CR_INK}" stroke-width="9" fill="none" stroke-linecap="round"/><path d="M68 86c16 0 21-14 13-24" stroke="#3A2E34" stroke-width="5.5" fill="none" stroke-linecap="round"/><path d="M30 90c-4-18 0-30 10-37h20c10 7 14 19 10 37z" fill="#3A2E34" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><ellipse cx="50" cy="76" rx="10" ry="11" fill="#4A3A42"/><path d="M33 37l-2-19 15 11zM67 37l2-19-15 11z" fill="#3A2E34" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M35 32l-1-8 6 5zM65 32l1-8-6 5z" fill="#FF6B57" opacity=".6"/><ellipse cx="50" cy="45" rx="21" ry="18" fill="#3A2E34" stroke="${CR_INK}" stroke-width="1.8"/><ellipse cx="42" cy="44" rx="5.5" ry="6.5" fill="#6EDBA8" stroke="${CR_INK}" stroke-width="1.6"/><ellipse cx="58" cy="44" rx="5.5" ry="6.5" fill="#6EDBA8" stroke="${CR_INK}" stroke-width="1.6"/><ellipse cx="42" cy="44.5" rx="1.5" ry="5" fill="${CR_INK}"/><ellipse cx="58" cy="44.5" rx="1.5" ry="5" fill="${CR_INK}"/><circle cx="40.2" cy="41.5" r="1.4" fill="#fff"/><circle cx="56.2" cy="41.5" r="1.4" fill="#fff"/><path d="M48 51.5h4l-2 2.4z" fill="#F0B8C4"/><path d="M50 54q-2.5 3-5 1M50 54q2.5 3 5 1" stroke="#E9DFC9" stroke-width="1.2" fill="none" stroke-linecap="round"/><path d="M36 51l-11-2M36 54l-11 2M64 51l11-2M64 54l11 2" stroke="#E9DFC9" stroke-width="1" opacity=".7" stroke-linecap="round"/></svg>`,
  spider:`<svg viewBox="0 0 100 100" width="100" height="100"><path d="M50 2v34" stroke="#E9DFC9" stroke-width="1.2" opacity=".6"/><g fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M40 50Q26 34 14 42M39 55Q22 48 10 58M40 60Q24 64 14 76M43 65Q32 76 26 88M60 50Q74 34 86 42M61 55Q78 48 90 58M60 60Q76 64 86 76M57 65Q68 76 74 88" stroke="${CR_INK}" stroke-width="6"/><path d="M40 50Q26 34 14 42M39 55Q22 48 10 58M40 60Q24 64 14 76M43 65Q32 76 26 88M60 50Q74 34 86 42M61 55Q78 48 90 58M60 60Q76 64 86 76M57 65Q68 76 74 88" stroke="#52465A" stroke-width="3"/></g><ellipse cx="50" cy="67" rx="17" ry="18" fill="#3B3140" stroke="${CR_INK}" stroke-width="1.8"/><path d="M46 60h8l-4 7 4 7h-8l4-7z" fill="#FF6B57" stroke="${CR_INK}" stroke-width="1.2" stroke-linejoin="round"/><ellipse cx="50" cy="46" rx="13" ry="11" fill="#4A3A48" stroke="${CR_INK}" stroke-width="1.8"/>${crEye(45,46,4.6,'#FF6B57')}${crEye(55,46,4.6,'#FF6B57')}<circle cx="42.5" cy="39.5" r="1.8" fill="#FF6B57"/><circle cx="57.5" cy="39.5" r="1.8" fill="#FF6B57"/><path d="M47 54.5l1 3 1.3-2.4zM50.7 55.1l1.3 2.4 1-3z" fill="#E9DFC9"/></svg>`,
  skull:`<svg viewBox="0 0 100 100" width="100" height="100"><path d="M50 13C30 13 19 27 19 44c0 12 6 20 15 24v12c0 3 2 5 5 5h22c3 0 5-2 5-5V68c9-4 15-12 15-24 0-17-11-31-31-31z" fill="#EEE6DC" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M70 22c6 6 11 13 11 22 0 12-6 20-15 24v12c0 3-2 5-5 5h-3V62c8-4 13-12 13-22 0-7-1-13-1-18z" fill="#D7CDC8" opacity=".7"/><ellipse cx="36" cy="25" rx="6" ry="3.2" fill="#fff" opacity=".75" transform="rotate(-25 36 25)"/><ellipse cx="38.5" cy="46" rx="8.5" ry="9.5" fill="${CR_INK}"/><ellipse cx="61.5" cy="46" rx="8.5" ry="9.5" fill="${CR_INK}"/><circle cx="39.5" cy="47" r="3.6" fill="#FF6B57"/><circle cx="60.5" cy="47" r="3.6" fill="#FF6B57"/><circle cx="38.3" cy="45.6" r="1.2" fill="#fff"/><circle cx="59.3" cy="45.6" r="1.2" fill="#fff"/><path d="M50 57l-4.5 7h9z" fill="${CR_INK}"/><path d="M38 75h24M44 75v10M50 75v10M56 75v10" stroke="${CR_INK}" stroke-width="1.6" stroke-linecap="round"/><path d="M58 15l-3 8 5 4-2 5" stroke="${CR_INK}" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  zombie:`<svg viewBox="0 0 100 100" width="100" height="100"><path d="M44 82V58c0-4 2-6 6-6s6 2 6 6v24z" fill="#7DB38A" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><path d="M41 70h18l-2 7-4-4-3 5-3-5-4 4z" fill="#6B4549" stroke="${CR_INK}" stroke-width="1.5" stroke-linejoin="round"/><path d="M39 43c-7-1-10-8-7-11 3 1 5 4 8 5z" fill="#7DB38A" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><rect x="38" y="31" width="25" height="25" rx="9" fill="#7DB38A" stroke="${CR_INK}" stroke-width="1.8"/><rect x="39.5" y="15" width="6" height="21" rx="3" fill="#7DB38A" stroke="${CR_INK}" stroke-width="1.8"/><rect x="46.5" y="10" width="6" height="25" rx="3" fill="#7DB38A" stroke="${CR_INK}" stroke-width="1.8"/><rect x="53.5" y="13" width="6" height="22" rx="3" fill="#7DB38A" stroke="${CR_INK}" stroke-width="1.8"/><rect x="59" y="20" width="5.5" height="17" rx="2.75" fill="#7DB38A" stroke="${CR_INK}" stroke-width="1.8" transform="rotate(12 61.75 28.5)"/><path d="M40.5 16.5h4M47.5 11.5h4M54.5 14.5h4" stroke="#4E7A5A" stroke-width="2" stroke-linecap="round"/><path d="M44 42l6 6M47 39v4M53 44h4" stroke="#4E7A5A" stroke-width="1.6" stroke-linecap="round"/><path d="M12 90c8-11 22-14 34-12 4 1 8 1 12 0 12-2 26 1 30 12z" fill="#4A3235" stroke="${CR_INK}" stroke-width="1.8" stroke-linejoin="round"/><circle cx="26" cy="84" r="2.2" fill="#6B4549"/><circle cx="72" cy="83" r="2.6" fill="#6B4549"/><circle cx="62" cy="87" r="1.6" fill="#6B4549"/><circle cx="34" cy="80" r="1.4" fill="#6B4549"/></svg>`
};
const CREATURE_KEYS=Object.keys(CREATURES);

// Crypt Keeper trash talk
const KEEPER_LINES=[
  'yeah, i see you.<br>got any subs to bury?',
  'don\'t just click me.<br>go cancel something.',
  'i\'ve got room in the graveyard.<br>who\'s next?',
  'every subscription fears me.<br>as they should.',
  'my lantern burns brighter<br>with every cancellation.',
  'you\'re doing the lord\'s work.<br>the dark lord, but still.',
  'between us?<br>i\'m proud of you.',
  'that subscription had it coming.<br>they all do.',
  'i don\'t do freebies.<br>but you\'re saving plenty.',
  'the graveyard grows...<br>your wallet thanks you.',
  'click me again.<br>i dare you.',
  'stop clicking me<br>and go cancel something.',
];

// Context-aware lines based on progress
const KEEPER_PROGRESS_LINES=[
  {min:0,max:0,line:'the graveyard is empty...<br>time to start burying.'},
  {min:1,max:49,line:'a few graves dug.<br>but i want MORE.'},
  {min:50,max:99,line:'now we\'re talking.<br>keep the tombstones coming.'},
  {min:100,max:199,line:'impressive graveyard.<br>the subs fear you.'},
  {min:200,max:499,line:'you are a true gravedigger.<br>the keeper approves.'},
  {min:500,max:99999,line:'i bow before you,<br>grim reaper of subscriptions.'},
];

// ===== STATE =====
// Signed in = currentUser is set. The session itself lives in the HttpOnly
// sg_session cookie, which page scripts can't read.
let currentUser=null,subs=[],deathRow=[];
let seenMilestones=JSON.parse(localStorage.getItem('sg_milestones')||'[]');
let keeperAnimTimeout;

// ===== API =====
// The three 401 messages that mean "this session is no longer good" (no token,
// expired signature, token_version bumped by a password change or reset).
const SESSION_401=['Unauthorized','Invalid or expired token','Token revoked'];
function sessionEnded(){
  if(!currentUser)return;
  closeAllOverlays();
  logout();
  showAuthErr('Your session ended. Log in again.');
}
const NET_ERR="Can't reach the server. Check your connection and try again.";
async function api(path,method='GET',body=null,_proRetried=false){
  const opts={method,headers:{},credentials:'same-origin'};
  // Lets the server schedule renewal warnings against the user's real
  // calendar day instead of UTC. Deliberately a header on the normal API
  // call rather than a signup field: it needs no onboarding modal, it
  // backfills existing accounts, and it never touches the auth path.
  try{const tz=Intl.DateTimeFormat().resolvedOptions().timeZone;if(tz)opts.headers['X-Timezone']=tz;}catch(e){}
  const hubPro=localStorage.getItem('hub_pro_jwt');
  if(hubPro)opts.headers['X-Hub-Pro']=hubPro;
  if(body){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body);}
  let r;
  try{r=await fetch(`/api${path}`,opts);}
  catch(e){
    // fetch() only rejects when nothing answered: offline, DNS, worker down.
    // "Failed to fetch" is browser-speak; say what it means and what to do.
    const err=new Error(NET_ERR);err.network=true;throw err;
  }
  const data=await r.json().catch(()=>({}));
  // A session that is no longer good ends right here, whatever the caller was
  // doing: overlays closed, login shown, one plain message. Before this only
  // the boot path handled it, and only for two of the three messages.
  if(r.status===401&&SESSION_401.includes(data?.error)){
    sessionEnded();
    const err=new Error('Your session ended. Log in again.');
    err.sessionEnded=true;
    throw err;
  }
  if(r.status===402){
    // Pro rejected but we hold a hub token: one refresh + one retry, then stop.
    if(hubPro&&!_proRetried){
      const hadPro=hubTokenHasPro(hubPro);
      const refreshed=await refreshHubPro();
      if(refreshed===true)return api(path,method,body,true);
      // refreshed===false: the hub says this Pro is over, the token is gone and
      // the user is free now, so they get the normal gate with its upgrade
      // link. refreshed===null: the hub could not be reached, so the gate
      // shows the "paused" copy instead of selling Pro to someone who may
      // still have it.
      if(hadPro&&refreshed===null)showProPaused();
    }
    showProRequired(data?.feature);
    const err=new Error(data?.error||'Pro required');
    err.paymentRequired=true;
    err.feature=data?.feature;
    throw err;
  }
  if(!r.ok){
    const err=new Error(data.error||(r.status>=500?'Something went wrong on our end. Try again in a minute.':'Something went wrong. Try again.'));
    err.status=r.status;
    if(data.code)err.code=data.code;
    if(data.email)err.email=data.email;
    throw err;
  }
  return data;
}
function setSyncStatus(s){const d=document.getElementById('sync-dot');const t=document.getElementById('sync-txt');if(d){d.style.background=s==='syncing'?'var(--lamp)':s==='error'?'var(--blood)':'var(--money)';d.style.boxShadow=`0 0 4px ${s==='syncing'?'rgba(242,180,90,0.4)':s==='error'?'rgba(255,143,128,0.4)':'var(--money-glow)'}`;}if(t)t.textContent=s==='syncing'?'Saving...':s==='error'?'Error':'Synced';}

// ===== AUTH =====
const MAIL_FAIL_MSG="We couldn't send your code right now. Try Resend code in a minute, or contact support.";
let authMode='login';
let pendingVerifyEmail=null;
// The password typed at signup/login, held IN MEMORY ONLY (never storage) so
// the code step can send it: verify-code needs code + password.
// When it's missing (reload, Back from another tab), the code box shows its
// own password field instead.
let pendingVerifyPw=null;
// currentAuthView tracks the pre-auth screen's in-page steps (login/signup
// tab, or the verify-code box) for the back-button handling below. It mirrors
// currentTab's role for the post-auth main tabs.
let currentAuthView='login';
function pushAuthView(view,replace){
  const state={authView:view,mode:authMode,email:pendingVerifyEmail};
  const url=location.pathname+location.search;
  if(replace)history.replaceState(state,'',url);else history.pushState(state,'',url);
}
function authTab(mode,fromHistory){
  if(!fromHistory&&mode===currentAuthView)return; // no-op: already on this tab, don't push a duplicate entry
  if(!fromHistory)pendingVerifyPw=null;
  showGuestBox(false);
  currentAuthView=mode;
  authMode=mode;document.querySelectorAll('.auth-tab').forEach((t,i)=>t.classList.toggle('active',mode==='login'?i===0:i===1));document.getElementById('auth-submit-btn').textContent=mode==='login'?'Log In':'Create Account';document.getElementById('auth-pw').autocomplete=mode==='login'?'current-password':'new-password';
  // Confirm-password only matters on sign up. Hide + clear it on login so a
  // stale value can't block a later sign up.
  const pw2Wrap=document.getElementById('auth-pw2-wrap');
  if(pw2Wrap)pw2Wrap.style.display=mode==='signup'?'block':'none';
  const pw2=document.getElementById('auth-pw2');
  if(pw2&&mode==='login')pw2.value='';
  const pwHint=document.getElementById('auth-pw-hint');
  if(pwHint)pwHint.style.display=mode==='signup'?'block':'none';
  const consent=document.getElementById('signup-consent');
  if(consent)consent.style.display=mode==='signup'?'block':'none';
  hideVerify();hideAuthMsg();
  if(!fromHistory)pushAuthView(mode);}
// Show the 6-digit code-entry box; hide the email/password form while verifying.
// A resend click re-calls this while already on the verify view (see
// resendVerify below) — the DOM reset (clear+refocus the code input) always
// runs, but a new history entry is only pushed the first time (wasVerify
// guard), so resend never stacks duplicate entries.
function showVerify(email,fromHistory){
  const wasVerify=currentAuthView==='verify';
  currentAuthView='verify';
  pendingVerifyEmail=email;document.getElementById('auth-form').style.display='none';document.getElementById('auth-forgot-btn').style.display='none';document.getElementById('verify-block').style.display='';document.getElementById('verify-code-input').value='';document.getElementById('verify-code-input').focus();
  const vpw=document.getElementById('verify-pw-wrap');if(vpw)vpw.style.display=pendingVerifyPw?'none':'';
  if(!fromHistory&&!wasVerify)pushAuthView('verify');
}
// DOM-only reversal of showVerify — no history side effects, safe to call
// from authTab() (a real, separately-pushing transition) and from
// restoreAuthView() (a popstate baseline reset) without either fighting
// over history entries.
function hideVerify(){pendingVerifyEmail=null;const vpi=document.getElementById('verify-pw-input');if(vpi)vpi.value='';const vb=document.getElementById('verify-block');if(vb)vb.style.display='none';const af=document.getElementById('auth-form');if(af)af.style.display='';const fb=document.getElementById('auth-forgot-btn');if(fb)fb.style.display='';}
function showAuthErr(m){const e=document.getElementById('auth-err');e.textContent=m;e.style.display='block';document.getElementById('auth-suc').style.display='none';}
function showAuthSuc(m){const e=document.getElementById('auth-suc');e.textContent=m;e.style.display='block';document.getElementById('auth-err').style.display='none';}
function hideAuthMsg(){document.getElementById('auth-err').style.display='none';document.getElementById('auth-suc').style.display='none';}
async function authSubmit(e){
  e.preventDefault();
  const btn=document.getElementById('auth-submit-btn');
  btn.disabled=true;hideAuthMsg();
  const email=document.getElementById('auth-email').value.trim(),password=document.getElementById('auth-pw').value;
  // Inline validation (form is novalidate so errors render in-page, not as
  // browser-native tooltips).
  if(!email||!password){showAuthErr('Please enter your email and password.');btn.disabled=false;return;}
  if(authMode==='signup'&&(password.length<10||password.length>200)){
    showAuthErr('Password must be 10–200 characters.');btn.disabled=false;return;
  }
  if(authMode==='signup'&&password!==(document.getElementById('auth-pw2')||{}).value){
    showAuthErr('Passwords do not match. Please re-type them.');btn.disabled=false;return;
  }
  try{
    if(authMode==='signup'){
      const d=await api('/auth/signup','POST',{email,password});
      if(d&&d.hub_pro_token)localStorage.setItem('hub_pro_jwt',d.hub_pro_token);
      if(d.user){currentUser=d.user;carryGuestOnEntry=true;showApp();}
      else{pendingVerifyPw=password;showVerify(d.email||email);if(d.email_sent===false)showAuthErr(MAIL_FAIL_MSG);else showAuthSuc('Check your inbox for a 6-digit code.');}
    }else{
      const d=await api('/auth/login','POST',{email,password});
      // The login response may carry a hub Pro token (Pro follows the account,
      // not the browser) — same localStorage slot as the ?hubpro= hand-off.
      if(d&&d.hub_pro_token)localStorage.setItem('hub_pro_jwt',d.hub_pro_token);
      currentUser=d.user;carryGuestOnEntry=true;showApp();
    }
  }catch(err){
    if(err.code==='email_not_verified'){
      pendingVerifyPw=password;
      showVerify(err.email||email);
      showAuthSuc('Enter the 6-digit code from your email to finish verifying.');
    }else{showAuthErr(err.message);}
  }
  btn.disabled=false;
}
// Verify the 6-digit code; on success the server sets the session cookie, so we
// log the user straight in exactly like a normal login.
async function submitVerifyCode(){
  const email=pendingVerifyEmail||document.getElementById('auth-email').value.trim();
  const code=document.getElementById('verify-code-input').value.replace(/\D/g,'');
  const btn=document.getElementById('verify-code-btn');
  if(code.length!==6){showAuthErr('Enter the 6-digit code from your email.');return;}
  const pwInput=document.getElementById('verify-pw-input');
  const password=pendingVerifyPw||(pwInput?pwInput.value:'');
  if(!password){
    const vpw=document.getElementById('verify-pw-wrap');if(vpw)vpw.style.display='';
    showAuthErr('Enter your password along with the code.');if(pwInput)pwInput.focus();return;
  }
  btn.disabled=true;hideAuthMsg();
  try{
    const d=await api('/auth/verify-code','POST',{email,code,password});
    if(d&&d.hub_pro_token)localStorage.setItem('hub_pro_jwt',d.hub_pro_token);
    pendingVerifyPw=null;currentUser=d.user;carryGuestOnEntry=true;hideVerify();showApp();
  }catch(err){
    if(err.code==='already_verified'||err.message.includes('already verified')){
      hideVerify();authTab('login');showAuthSuc('Your email is verified. Please log in.');
    }else{
      // Wrong password: drop the remembered one and let them type it here.
      if(/password/i.test(err.message||'')){pendingVerifyPw=null;const vpw=document.getElementById('verify-pw-wrap');if(vpw)vpw.style.display='';if(pwInput){pwInput.value='';pwInput.focus();}}
      showAuthErr(err.message);
    }
  }
  btn.disabled=false;
}
async function resendVerify(email){
  try{const d=await api('/auth/resend-verification','POST',{email});showVerify(email);if(d&&d.email_sent===false)showAuthErr(MAIL_FAIL_MSG);else showAuthSuc('A new code is on its way. Check your inbox.');}
  catch(err){showAuthErr(err.message);}
}
async function forgotPw(){const email=document.getElementById('auth-email').value.trim();if(!email){showAuthErr('Enter your email first');return;}try{await api('/auth/reset-request','POST',{email});showAuthSuc('Check your email for a reset link.');}catch(err){showAuthErr(err.message);}}
function logout(){currentUser=null;subs=[];deathRow=[];
  // A sample left on a shared device must not wait for the next person.
  clearGuestSub();clearGuestDraft();carryGuestOnEntry=false;
  // The server clears the HttpOnly cookie (the page can't). keepalive lets
  // it finish even if the user closes the tab right after.
  fetch('/api/auth/logout',{method:'POST',credentials:'same-origin',keepalive:true}).catch(()=>{});
  try{localStorage.removeItem('sg_token');}catch(e){}
  // The hub Pro token is a credential too: init() exchanges it for a session
  // through hub-sso, so leaving it behind meant "log out" silently logged the
  // user straight back in on the next load.
  localStorage.removeItem('hub_pro_jwt');proPaused=false;
  setFeedbackVisible(false);stopCritters();document.getElementById('app-outer').style.display='none';document.getElementById('auth-screen').style.display='flex';
  // Collapse history to a clean auth landing state. Without this, the tab
  // entries pushed during the session are still on top of the stack — a
  // post-logout Back press would pop one of them, and since the app DOM is
  // now hidden, that's a dead click. replaceState() here means the very
  // next Back press correctly exits the site instead.
  hideVerify();authTab('login',true);pushAuthView('login',true);
}

// ===== GUEST SAMPLE BURIAL (UX fixes 2026-11) =====
// A logged-out visitor buries ONE sample subscription before any sign-up form.
// It never touches the server while they're a guest: it sits in localStorage
// and goes through the normal authed POST /api/subscriptions (same validation
// and free cap as every other burial) right after an interactive sign-up,
// verify or log-in on this page. Everything read back out of storage is
// re-validated, because anything on the device can edit it.
const GUEST_KEY='sg_guest_sub';
// 2 hours: an unsaved sample on a shared device expires
// instead of landing in the next person's account. Log-out clears it too.
const GUEST_MAX_AGE_MS=2*3600000;
const GUEST_NAME_MAX=60,GUEST_COST_MAX=10000;
function dateDaysAgo(n){const d=new Date(todayStr()+'T12:00:00');d.setDate(d.getDate()-n);return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');}
function readGuestSub(){
  let g=null;
  try{g=JSON.parse(localStorage.getItem(GUEST_KEY)||'null');}catch(e){g=null;}
  if(!g||typeof g!=='object'){clearGuestSub();return null;}
  const name=typeof g.name==='string'?g.name.trim():'';
  const ok=g.v===1&&name.length>=1&&name.length<=GUEST_NAME_MAX
    &&typeof g.cost==='number'&&isFinite(g.cost)&&g.cost>0&&g.cost<=GUEST_COST_MAX
    &&typeof g.date==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(g.date)
    &&g.date<=todayStr()&&g.date>=dateDaysAgo(1)
    &&typeof g.at==='number'&&Date.now()-g.at<GUEST_MAX_AGE_MS&&g.at<=Date.now()+60000;
  if(!ok){clearGuestSub();return null;}
  return {v:1,name,cost:Math.round(g.cost*100)/100,date:g.date,at:g.at};
}
function saveGuestSub(g){try{localStorage.setItem(GUEST_KEY,JSON.stringify(g));}catch(e){}}
function clearGuestSub(){try{localStorage.removeItem(GUEST_KEY);}catch(e){}}
// What they've typed on the try view before pressing Bury it, kept for this tab
// only (sessionStorage), so opening the guide or a legal page and pressing Back
// doesn't wipe it. Gone with the tab.
const GUEST_DRAFT_KEY='sg_guest_draft';
function saveGuestDraft(){try{sessionStorage.setItem(GUEST_DRAFT_KEY,JSON.stringify({name:String(document.getElementById('guest-name').value).slice(0,GUEST_NAME_MAX),cost:String(document.getElementById('guest-cost').value).slice(0,12)}));}catch(e){}}
function clearGuestDraft(){try{sessionStorage.removeItem(GUEST_DRAFT_KEY);}catch(e){}}
function restoreGuestDraft(){
  let d=null;try{d=JSON.parse(sessionStorage.getItem(GUEST_DRAFT_KEY)||'null');}catch(e){d=null;}
  if(!d||typeof d!=='object')return;
  const n=document.getElementById('guest-name'),c=document.getElementById('guest-cost');
  if(n&&!n.value&&typeof d.name==='string')n.value=d.name.slice(0,GUEST_NAME_MAX);
  if(c&&!c.value&&typeof d.cost==='string'&&/^\d{0,5}(\.\d{0,2})?$/.test(d.cost))c.value=d.cost;
}
// Armed only by an interactive sign-up, verify or log-in on this page, never by
// a silent boot session or hub sign-in, so a sample left behind on a shared
// device can't slip into whoever happens to be signed in next.
let carryGuestOnEntry=false;
async function carryGuestSub(){
  const g=readGuestSub();
  if(!g)return;
  // Free holds 5. Skip the POST (and its upgrade pop-up) for a full free graveyard.
  if(subs.length>=5&&!localStorage.getItem('hub_pro_jwt')){
    clearGuestSub();
    showToast('Your free graveyard is full, so '+g.name+' stayed out');
    return;
  }
  try{
    const sub=await api('/subscriptions','POST',{name:g.name,monthly_cost:g.cost,category:'other',cancelled_date:g.date});
    subs.push(sub);clearGuestSub();
    // They already had their first-burial moment as a guest.
    if(!seenMilestones.includes('first-kill')){seenMilestones.push('first-kill');try{localStorage.setItem('sg_milestones',JSON.stringify(seenMilestones));}catch(e){}}
    showToast(g.name+' moved into your graveyard');
  }catch(err){
    if(err.paymentRequired){clearGuestSub();return;}
    // The server said no to the data itself: drop it rather than retry forever.
    // A dropped connection, a rate limit or a 5xx keeps it for the next sign-in.
    if(err.status>=400&&err.status<500&&err.status!==429)clearGuestSub();
  }
}
// Guest views ('try' -> 'result'). Same history pattern as the auth steps:
// replaceState for the landing view, pushState per move in, popstate restores
// through showGuest(view,{fromHistory:true}).
let guestView=null;
function showGuestBox(on){
  const g=document.getElementById('guest-box'),a=document.getElementById('auth-box');
  if(g)g.hidden=!on;if(a)a.hidden=on;
  if(!on){guestView=null;paintGuestNote();}
}
// On the log-in / sign-up card: say the sample is waiting, or offer the try.
function paintGuestNote(){
  const g=readGuestSub();
  const note=document.getElementById('guest-carry-note');
  if(note){note.hidden=!g;note.textContent=g?'Your '+g.name+' tombstone is waiting. Sign up or log in and it moves into your graveyard.':'';}
  const link=document.getElementById('guest-try-link');if(link)link.hidden=!!g;
}
function showGuest(view,opts={}){
  const {replace=false,fromHistory=false}=opts;
  if(view!=='try'&&view!=='result')view='try';
  if(view==='result'&&!readGuestSub())view='try';
  if(!fromHistory&&!replace&&view===guestView)return; // no-op: already here
  showGuestBox(true);
  currentAuthView=null; // so the next authTab() always gets its own entry
  guestView=view;
  document.getElementById('guest-try').hidden=view!=='try';
  document.getElementById('guest-result').hidden=view!=='result';
  if(view==='try')renderGuestTry();else renderGuestResult();
  if(!fromHistory){
    const st={guestView:view},url=location.pathname+location.search;
    if(replace)history.replaceState(st,'',url);else history.pushState(st,'',url);
  }
}
function renderGuestTry(){
  const e=document.getElementById('guest-err');if(e){e.textContent='';e.style.display='none';}
  const g=readGuestSub();
  if(g){document.getElementById('guest-name').value=g.name;document.getElementById('guest-cost').value=g.cost;}
  else restoreGuestDraft();
}
function guestBury(e){
  if(e)e.preventDefault();
  const name=document.getElementById('guest-name').value.trim();
  const cost=parseFloat(document.getElementById('guest-cost').value);
  const err=document.getElementById('guest-err');
  const fail=(m)=>{err.textContent=m;err.style.display='block';};
  if(!name){fail('Type the name of something you canceled.');document.getElementById('guest-name').focus();return;}
  if(name.length>GUEST_NAME_MAX){fail('Keep the name under '+GUEST_NAME_MAX+' characters.');return;}
  if(!isFinite(cost)||cost<=0){fail('Add what it cost you a month.');document.getElementById('guest-cost').focus();return;}
  if(cost>GUEST_COST_MAX){fail('That price looks too high. Use the monthly amount.');return;}
  saveGuestSub({v:1,name,cost:Math.round(cost*100)/100,date:todayStr(),at:Date.now()});
  clearGuestDraft();
  showGuest('result');
}
function renderGuestResult(){
  const g=readGuestSub();if(!g)return;
  document.getElementById('guest-tomb-name').textContent=g.name;
  document.getElementById('guest-tomb-saved').textContent='saves '+fmt(g.cost);
  document.getElementById('guest-amt').textContent=fmt(g.cost)+'/mo';
  document.getElementById('guest-bubble').textContent='rest in peace, '+g.name+'. that\'s '+fmt(g.cost*12)+' a year you keep.';
  // The bar fills toward the next rank, the same ranks the app uses.
  const tier=getTier(g.cost);
  const next=[...TIERS].reverse().find(t=>t.min>g.cost);
  const pct=next?Math.max(4,Math.round(g.cost/next.min*100)):100;
  document.getElementById('guest-rank').textContent=next?tier.label+' rank. '+next.label+' starts at $'+next.min+' a month.':tier.label+' rank. That\'s the top one.';
  const fill=document.getElementById('guest-fill');
  fill.style.width='0%';
  // Two frames so the browser paints the empty bar before it fills.
  requestAnimationFrame(()=>requestAnimationFrame(()=>{fill.style.width=pct+'%';}));
  setTimeout(()=>{const r=fill.getBoundingClientRect();if(r.width)burst(r.right,r.top+r.height/2,10);},450);
}
// Out of the guest flow into the auth card (its own history entry).
function leaveGuestTo(mode){
  currentAuthView=null;
  authTab(mode==='signup'?'signup':'login');
}
// Landing on the auth card itself (replaceState, so Back still leaves the site).
function landAuth(mode){
  currentAuthView=null;
  authTab(mode,true);
  pushAuthView(mode,true);
}

// Reset token comes from the PATH (/reset/<token>). The old ?reset=<token> form
// is still read so links already sitting in inboxes keep working, but it is not
// what we send any more — see the quoted-printable note in the worker.
function getResetToken(){
  const m = location.pathname.match(/^\/reset\/([A-Za-z0-9._-]{16,256})\/?$/);
  if (m) return m[1];
  return new URLSearchParams(location.search).get('reset');
}
function checkResetToken(){const t=getResetToken();if(t){window._resetToken=t;hideBootScreen();document.getElementById('auth-screen').style.display='none';document.getElementById('reset-screen').style.display='flex';window.history.replaceState({},'',window.location.pathname);}}
async function confirmReset(){const pw=document.getElementById('reset-pw').value,el=document.getElementById('reset-err');if(!pw||pw.length<10||pw.length>200){el.textContent='Password must be 10-200 characters';el.style.display='block';return;}try{const d=await api('/auth/reset-confirm','POST',{token:window._resetToken,password:pw});if(d&&d.hub_pro_token)localStorage.setItem('hub_pro_jwt',d.hub_pro_token);currentUser=d.user;document.getElementById('reset-screen').style.display='none';
  // The token is used now. Take it out of the URL so a refresh lands on the
  // app instead of a reset form that can only say "invalid or expired".
  window._resetToken=null;history.replaceState({},'','/');
  showApp();}catch(err){el.textContent=err.message;el.style.display='block';}}

// ===== AMBIENT CRITTERS =====
// Occasional flyby on the Graveyard tab: one critter at a time, every 30-60s,
// non-interactive (pointer-events:none), fully disabled under
// prefers-reduced-motion, and skipped while the document is hidden.
const AMBIENT_KINDS=[
  {key:'bat',dur:9000,amp:70,waves:3,scale:.8,peak:.6},
  {key:'ghost',dur:16000,amp:26,waves:1.5,scale:.85,peak:.5},
  {key:'raven',dur:11000,amp:34,waves:2,scale:.75,peak:.55},
];
const reduceMotionMq=window.matchMedia?window.matchMedia('(prefers-reduced-motion: reduce)'):{matches:false};
let critterTimer=null,critterEl=null;
function graveyardTabVisible(){
  const app=document.getElementById('app-outer');
  const panel=document.getElementById('panel-graveyard');
  return !!(app&&app.style.display!=='none'&&panel&&panel.classList.contains('active'));
}
function scheduleCritter(){
  if(reduceMotionMq.matches)return;
  clearTimeout(critterTimer);
  critterTimer=setTimeout(spawnCritter,30000+Math.random()*30000);
}
function spawnCritter(){
  if(reduceMotionMq.matches)return;
  if(document.hidden||critterEl||!graveyardTabVisible()){scheduleCritter();return;}
  const kind=AMBIENT_KINDS[Math.floor(Math.random()*AMBIENT_KINDS.length)];
  const el=document.createElement('div');
  el.className='ambient-critter';
  el.setAttribute('aria-hidden','true');
  el.innerHTML=CREATURES[kind.key];
  document.body.appendChild(el);
  critterEl=el;
  const dir=Math.random()<.5?1:-1;
  const w=window.innerWidth;
  const startX=dir===1?-90:w+90;
  const endX=dir===1?w+90:-90;
  const baseY=window.innerHeight*(0.12+Math.random()*0.45);
  const frames=[];
  const steps=24;
  for(let i=0;i<=steps;i++){
    const t=i/steps;
    const x=startX+(endX-startX)*t;
    const y=baseY+Math.sin(t*Math.PI*kind.waves)*kind.amp;
    const fade=t<.08?t/.08:t>.92?(1-t)/.08:1;
    frames.push({transform:`translate(${x.toFixed(1)}px,${y.toFixed(1)}px) scale(${kind.scale}) scaleX(${dir})`,opacity:+(kind.peak*fade).toFixed(3),offset:t});
  }
  const anim=el.animate(frames,{duration:kind.dur,easing:'linear'});
  const done=()=>{if(critterEl===el)critterEl=null;el.remove();scheduleCritter();};
  anim.onfinish=done;
  anim.oncancel=done;
}
function stopCritters(){clearTimeout(critterTimer);critterTimer=null;if(critterEl){critterEl.remove();critterEl=null;}}
document.addEventListener('visibilitychange',()=>{
  if(document.hidden&&critterEl){critterEl.remove();critterEl=null;scheduleCritter();}
});
if(reduceMotionMq.addEventListener)reduceMotionMq.addEventListener('change',()=>{if(reduceMotionMq.matches)stopCritters();else if(currentUser)scheduleCritter();});

// ===== FEEDBACK WIDGET (logged-in users only, mirrors App Hub) =====
let feedbackLoaded=false;
function loadFeedbackWidget(){
  if(feedbackLoaded){setFeedbackVisible(true);return;}
  feedbackLoaded=true;
  const s=document.createElement('script');
  s.src='/feedback-widget.js?v=20260821a';
  s.defer=true;
  document.body.appendChild(s);
}
function setFeedbackVisible(show){document.querySelectorAll('.fbw-btn,.fbw-overlay').forEach(el=>{el.style.display=show?'':'none';});}

// ===== APP INIT =====
async function showApp(){hideBootScreen();document.getElementById('auth-screen').style.display='none';document.getElementById('app-outer').style.display='';
  // Landing tab is always Graveyard (static HTML default) — replaceState
  // (not pushState) so this doesn't consume a Back press; the very first
  // Back from here correctly leaves the app. This also collapses whatever
  // pre-auth step entry (login/signup/verify) was on top, so a just-logged-
  // in user's Back doesn't land on a stale auth-flow screen.
  // A refresh must leave you on the tab you were looking at. Browsers keep
  // history.state across a reload of the same entry, so the pushState from the
  // last tab switch is still readable here — read it before defaulting.
  // Without this, refreshing anywhere but the first tab bounced the user back
  // to it.
  // A FRESH LOGIN has no `view` in state — the top entry is the auth step — so
  // it still lands on the default, and the replaceState below still collapses
  // that auth entry, which is what this block was always protecting.
  // goTab(x, true) is the existing choke point: it does the DOM work and skips
  // the push. currentTab is nulled first so its no-op guard can't swallow it.
  currentTab=null;
  goTab(BOOT_VIEW||'graveyard',true);
  pushViewState(true);
  scheduleCritter();await loadAppData();}
// The first data load. When it fails for any reason other than the session
// ending, the shell is not left half-rendered: a banner says what happened and
// Retry runs this again. Before this the failure only turned the sync dot red.
let blinkStarted=false;
async function loadAppData(){
  try{
    setSyncStatus('syncing');
    if(!currentUser)currentUser=await api('/profile');
    const[s,d]=await Promise.all([api('/subscriptions'),api('/death-row')]);
    subs=s;deathRow=d;setSyncStatus('synced');showLoadBanner('');
    if(carryGuestOnEntry){carryGuestOnEntry=false;await carryGuestSub();}
    renderAll();syncKeeper();
    // Awaited so the onboarding question knows the free cap before it opens.
    await hydrateProStatus();
    if(!blinkStarted){blinkStarted=true;scheduleBlink();}
    if(!localStorage.getItem('sg_onboard_seen')){openOnboard();}else{setTimeout(maybeOfferTour,400);}
  }catch(err){
    if(err.sessionEnded)return;
    setSyncStatus('error');
    showLoadBanner(err.network?NET_ERR:"Your graveyard didn't load. "+err.message);
  }
}
function showLoadBanner(msg){
  const b=document.getElementById('load-banner'),t=document.getElementById('load-banner-msg');
  if(!b||!t)return;
  t.textContent=msg;b.style.display=msg?'flex':'none';
}
function closeOnboard(fromHistory){localStorage.setItem('sg_onboard_seen','1');if(!fromHistory&&popOverlayState())return;document.getElementById('onboard-overlay').style.display='none';setTimeout(maybeOfferTour,350);}


// ===== ONBOARDING QUESTION (UX fixes 2026-11) =====
// "What have you already canceled?" Tap-to-pick chips become their first
// tombstones through the normal POST /api/subscriptions. The API needs a real
// monthly price (no zero or unknown), so each pick gets its own price box.
// Opening it is one overlay history entry, so Back (or Escape, or Skip) closes it.
const OB_CHIPS=[
  {k:'streaming',label:'Streaming service',cat:'streaming'},
  {k:'music',label:'Music app',cat:'music'},
  {k:'gym',label:'Gym membership',cat:'fitness'},
  {k:'fitness-app',label:'Fitness app',cat:'fitness'},
  {k:'meal-kit',label:'Meal kit',cat:'food'},
  {k:'delivery',label:'Food delivery pass',cat:'food'},
  {k:'news',label:'News or magazine',cat:'news'},
  {k:'apps',label:'App or software',cat:'software'},
  {k:'storage',label:'Cloud storage',cat:'storage'},
  {k:'gaming',label:'Gaming pass',cat:'gaming'},
  {k:'audiobooks',label:'Audiobooks',cat:'audiobooks'},
  {k:'other',label:'Something else',cat:'other'},
];
let obPicked=[];
function obCap(){return isPro?OB_CHIPS.length:Math.max(0,5-subs.length);}
function openOnboard(){
  obPicked=[];
  document.getElementById('ob-rows').innerHTML='';
  const e=document.getElementById('ob-err');if(e){e.textContent='';e.style.display='none';}
  renderObChips();
  pushOverlayState();
  document.getElementById('onboard-overlay').style.display='flex';
}
function renderObChips(){
  const cap=obCap();
  document.getElementById('ob-chips').innerHTML=OB_CHIPS.map(c=>{
    const on=obPicked.includes(c.k);
    return `<button type="button" class="ob-chip" data-action="ob-chip" data-k="${esc(c.k)}" aria-pressed="${on}"${!on&&obPicked.length>=cap?' disabled':''}>${esc(c.label)}</button>`;
  }).join('');
  const hint=document.getElementById('ob-hint');
  hint.textContent=!isPro&&obPicked.length>=cap?(cap===0?'Your free graveyard already holds 5. Pro removes the cap.':'Free holds 5 tombstones in all. Pro removes the cap.'):'';
  const btn=document.getElementById('ob-bury-btn');
  btn.disabled=!obPicked.length;
  btn.textContent=obPicked.length>1?'Bury all '+obPicked.length:'Bury it';
}
function toggleObChip(k){
  const c=OB_CHIPS.find(x=>x.k===k);if(!c)return;
  const rows=document.getElementById('ob-rows');
  if(obPicked.includes(k)){
    obPicked=obPicked.filter(x=>x!==k);
    const row=rows.querySelector(`[data-k="${k}"]`);if(row)row.remove();
  }else{
    if(obPicked.length>=obCap())return;
    obPicked.push(k);
    const row=document.createElement('div');
    row.className='ob-row';row.dataset.k=k;
    const nameVal=k==='other'?'':c.label;
    row.innerHTML=`<input class="finput ob-name" type="text" maxlength="60" aria-label="Name for ${esc(c.label)}" placeholder="${k==='other'?'What was it?':esc(c.label)}" value="${esc(nameVal)}"/>`+
      `<input class="finput ob-cost" type="number" step="0.01" min="0.01" max="10000" inputmode="decimal" aria-label="Monthly price for ${esc(c.label)}" placeholder="$ a month"/>`;
    rows.appendChild(row);
    row.addEventListener('input',(ev)=>ev.target.classList.remove('ob-bad'));
    const nameIn=row.querySelector('.ob-name');
    nameIn.addEventListener('focus',()=>nameIn.select());
    (k==='other'?nameIn:row.querySelector('.ob-cost')).focus();
  }
  renderObChips();
}
async function obBury(){
  if(obBury.busy)return;
  const err=document.getElementById('ob-err');
  const fail=(m)=>{err.textContent=m;err.style.display='block';};
  err.style.display='none';
  const rows=[...document.querySelectorAll('#ob-rows .ob-row')];
  const items=[];let bad=null;
  for(const row of rows){
    const c=OB_CHIPS.find(x=>x.k===row.dataset.k);
    const nIn=row.querySelector('.ob-name'),cIn=row.querySelector('.ob-cost');
    const name=nIn.value.trim(),cost=parseFloat(cIn.value);
    nIn.classList.toggle('ob-bad',!name);
    const costBad=!isFinite(cost)||cost<=0||cost>10000;
    cIn.classList.toggle('ob-bad',costBad);
    if(!name||costBad){if(!bad)bad=!name?nIn:cIn;continue;}
    items.push({row,name,cost:Math.round(cost*100)/100,category:c?c.cat:'other'});
  }
  if(bad){fail('Each pick needs a name and what it cost a month. A close guess is fine.');bad.focus();return;}
  if(!items.length)return;
  obBury.busy=true;
  const btn=document.getElementById('ob-bury-btn');btn.disabled=true;
  setSyncStatus('syncing');
  let done=0;
  try{
    for(const it of items){
      const sub=await api('/subscriptions','POST',{name:it.name,monthly_cost:it.cost,category:it.category,cancelled_date:todayStr()});
      subs.push(sub);done++;
      obPicked=obPicked.filter(x=>x!==it.row.dataset.k);it.row.remove();
    }
    setSyncStatus('synced');
  }catch(ex){
    setSyncStatus(ex.paymentRequired||ex.sessionEnded?'synced':'error');
    if(done)renderAll();
    obBury.busy=false;
    if(ex.sessionEnded)return;
    renderObChips();
    if(!ex.paymentRequired)fail(ex.message);
    return;
  }
  obBury.busy=false;
  if(!seenMilestones.includes('first-kill')){seenMilestones.push('first-kill');try{localStorage.setItem('sg_milestones',JSON.stringify(seenMilestones));}catch(e){}}
  closeOnboard();
  renderAll();goTab('graveyard',true);
  showToast(done===1?'1 buried. Your graveyard is open.':done+' buried. Your graveyard is open.');
  reactKeeper('pleased');
  const wrap=document.querySelector('.character-wrap');if(wrap){const r=wrap.getBoundingClientRect();burst(r.left+r.width/2,r.top+80,15);}
}

// ===== TAB SWITCHING =====
// Single choke point for main-tab navigation (graveyard/deathrow/dashboard/
// add/watchlist). `fromHistory` is set only by the popstate handler below
// (restoring a prior tab) — it skips the pushState call so restoring never
// re-pushes (loop guard). showApp() does a one-time replaceState for the
// landing tab; every other call here that changes the tab pushes a new
// entry, so the browser Back button steps through tabs the user actually
// visited instead of exiting the app.
let currentTab='graveyard';
function pushViewState(replace){
  const state={view:currentTab};
  const url=location.pathname+location.search;
  if(replace)history.replaceState(state,'',url);else history.pushState(state,'',url);
}
function goTab(tab,fromHistory){
  if(!['graveyard','deathrow','dashboard','add','watchlist'].includes(tab))tab='graveyard';
  if(!fromHistory&&tab===currentTab)return; // no-op: already on this tab, don't push a duplicate entry
  currentTab=tab;
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));document.getElementById('panel-'+tab).classList.add('active');document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===tab));if(tab==='dashboard')renderDashboard();
  if(!fromHistory)pushViewState();
}

// ===== HELPERS =====
function fmt(n){return'$'+Number(n).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});}
function fmtShort(n){return n>=1000?'$'+(n/1000).toFixed(1)+'k':'$'+Math.round(n);}
// toISOString() is UTC. For anyone west of UTC that rolls over early: burying
// a sub at 8pm Pacific recorded TOMORROW's date, so the tombstone showed the
// wrong cancellation date and "days buried" was off by one. executeDR() passes
// this straight through with no user input, so there was nothing to correct it.
// en-CA gives YYYY-MM-DD, which is the format the API and <input type="date">
// both want. There is no stored timezone on the user record, so use the one the
// browser resolves — that is the calendar the user is actually looking at.
function todayStr(){
  try{
    return new Intl.DateTimeFormat('en-CA',{timeZone:Intl.DateTimeFormat().resolvedOptions().timeZone}).format(new Date());
  }catch(e){
    return new Date().toISOString().slice(0,10);
  }
}
function calcSavings(sub){const d=Math.max(0,Math.floor((new Date()-new Date(sub.cancelled_date+'T00:00:00'))/86400000));return{totalSaved:sub.monthly_cost*(d/30.44),daysDead:d};}
function calcLifetimeCost(sub){if(!sub.started_date)return null;return sub.monthly_cost*Math.max(0,(new Date(sub.cancelled_date+'T00:00:00')-new Date(sub.started_date+'T00:00:00'))/(86400000*30.44));}
function totalMonthlySavings(){return subs.reduce((s,sub)=>s+sub.monthly_cost,0);}
function totalSaved(){return subs.reduce((s,sub)=>s+calcSavings(sub).totalSaved,0);}
function getTier(r){return TIERS.find(t=>r>=t.min)||TIERS[TIERS.length-1];}
function getTombstoneAge(d){if(d>=365)return{cls:'tomb-ancient',label:'legendary',tip:'Buried a year or more'};if(d>=180)return{cls:'tomb-weathered',label:'weathered',tip:'Buried 6 months or more'};if(d>=30)return{cls:'tomb-established',label:'resting',tip:'Buried 1 to 6 months'};return{cls:'tomb-fresh',label:'fresh',tip:'Buried less than a month ago'};}
function populateCategoryDropdowns(){const h=CATEGORIES.map(c=>`<option value="${c.value}">${c.label}</option>`).join('');['add-cat','dr-cat'].forEach(id=>document.getElementById(id).innerHTML=h);}
function showToast(msg){const t=document.createElement('div');t.className='toast';t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),2500);}
function showPrivacy(){pushOverlayState();document.getElementById('privacy-modal').style.display='flex';}
function hidePrivacy(fromHistory){if(!fromHistory&&popOverlayState())return;document.getElementById('privacy-modal').style.display='none';}
function openDeleteModal(){pushOverlayState();setDeleteMode(false);document.getElementById('delete-modal').style.display='flex';}
// Password accounts type their password. App Hub accounts that never set one
// switch to "type DELETE" and the hub token on this device is checked instead.
let deleteViaHub=false;
function setDeleteMode(viaHub){deleteViaHub=!!viaHub;const pr=document.getElementById('delete-pw-row'),hr=document.getElementById('delete-hub-row');if(pr)pr.style.display=deleteViaHub?'none':'block';if(hr)hr.style.display=deleteViaHub?'block':'none';const err=document.getElementById('delete-err');if(err){err.textContent='';err.style.display='none';}const f=document.getElementById(deleteViaHub?'delete-confirm-text':'delete-pw');if(f)setTimeout(()=>f.focus(),0);}
// Change password (Account settings). PUT /api/auth/password bumps the
// token_version, which ends every other session, and sets a fresh session
// cookie for this one so the person stays logged in here.
function openPasswordModal(){pushOverlayState();document.getElementById('password-modal').style.display='flex';}
function closePasswordModal(fromHistory){
  ['pw-current','pw-new'].forEach(id=>{const i=document.getElementById(id);if(i)i.value='';});
  const err=document.getElementById('pw-err');if(err){err.textContent='';err.style.display='none';}
  if(!fromHistory&&popOverlayState())return;
  const m=document.getElementById('password-modal');if(m)m.style.display='none';
}
async function savePassword(e){
  if(e)e.preventDefault();
  const cur=document.getElementById('pw-current').value,nw=document.getElementById('pw-new').value;
  const err=document.getElementById('pw-err'),btn=document.getElementById('pw-save-btn');
  const fail=(m)=>{err.textContent=m;err.style.display='block';};
  if(!cur){fail('Enter your current password.');return;}
  if(nw.length<10||nw.length>200){fail('Your new password needs 10 to 200 characters.');return;}
  btn.disabled=true;
  try{
    const d=await api('/auth/password','PUT',{current_password:cur,password:nw});
    // The server set a fresh session cookie with the new token_version.
    closePasswordModal();
    showToast('Password changed');
  }catch(ex){fail(ex.message);}
  btn.disabled=false;
}
// Styled confirm — replaces native confirm() for destructive actions.
let _confirmResolve=null;
function showConfirm(title,msg,okLabel,cancelLabel){
  return new Promise(resolve=>{
    const m=document.getElementById('confirm-modal');
    if(!m){resolve(window.confirm(msg));return;}
    document.getElementById('confirm-title').textContent=title;
    document.getElementById('confirm-msg').textContent=msg;
    document.getElementById('confirm-ok-btn').textContent=okLabel||'dig it up';
    document.getElementById('confirm-cancel-btn').textContent=cancelLabel||'leave it be';
    _confirmResolve=resolve;
    pushOverlayState();
    m.style.display='flex';
  });
}
// Resolves FIRST, then closes. Order matters: if this routed through
// history.back() before resolving, popstate's closeAllOverlays() would reach
// resolveConfirm(false) first and the user's actual answer would be lost.
// Resolving up front makes the popstate pass a no-op for the promise.
function resolveConfirm(val,fromHistory){
  if(_confirmResolve){_confirmResolve(val);_confirmResolve=null;}
  if(!fromHistory&&popOverlayState())return;
  const m=document.getElementById('confirm-modal');
  if(m)m.style.display='none';
}
// Negotiation script modal — static copy; name/date go in via textContent (no HTML).
function showNegotiationScript(name,date){
  const m=document.getElementById('negotiate-modal');
  if(!m)return;
  const sub=document.getElementById('negotiate-sub');
  if(sub)sub.textContent=`${name} renews on ${date}. The renewal window is when you have the upper hand.`;
  pushOverlayState();
  m.style.display='flex';
}
function closeNegotiate(fromHistory){if(!fromHistory&&popOverlayState())return;const m=document.getElementById('negotiate-modal');if(m)m.style.display='none';}
function renderAll(){renderGraveyard();renderDeathRow();renderDashboard();renderAppTip();renderDailyTip();populateCategoryDropdowns();syncKeeper();paintAccount();}
function paintAccount(){const e=document.getElementById('acct-email');if(e&&currentUser)e.textContent=currentUser.email;}

// ===== HELP PANEL =====
// Re-openable forever from the ? in the header. Routes through the overlay
// history helpers so Back and Escape close it instead of leaving the app.
function openHelp(){
  const m=document.getElementById('help-modal');
  if(!m)return;
  const body=m.querySelector('.help-body');
  if(body)body.scrollTop=0;
  pushOverlayState();
  m.style.display='flex';
  const done=m.querySelector('.help-done');
  if(done)done.focus();
}
// fromHistory=true means popstate is already unwinding the entry — hide
// directly, or calling history.back() again would loop.
function closeHelp(fromHistory){
  if(!fromHistory&&popOverlayState())return;
  const m=document.getElementById('help-modal');
  if(m)m.style.display='none';
}

// ===== GUIDED TOUR =====
// Each stop highlights a real element with a ring and pins an explainer to the
// bottom. Takes exactly ONE history entry for the whole run, so Back ends the
// tour and leaves you on the app; per-stop entries would replay it backwards.
const TOUR_STOPS=[
  {tab:null,sel:null,text:"new here? i'm the Crypt Keeper. let me show you around. six quick stops, or skip any time."},
  {tab:'graveyard',sel:'.keeper-panel',text:"that's me, and that's your monthly savings. it goes up every time you bury something."},
  {tab:'graveyard',sel:'#graveyard-content',text:"the graveyard. one tombstone per canceled subscription, each counting what it has saved you since the day it died."},
  {tab:'add',sel:'#panel-add',text:"this is where a canceled sub becomes a tombstone. name, cost, category. the start date is optional but it shows what the thing cost you overall."},
  {tab:'deathrow',sel:'#panel-deathrow',text:"Last Rites is the waiting room: subs you know you should cancel and haven't. park them here and they stop being invisible."},
  {tab:'dashboard',sel:'#panel-dashboard',text:"Stats is the whole picture. monthly savings, total saved, and where the money was going."},
  {tab:'watchlist',sel:'#panel-watchlist',text:"renewal alerts warn you before an active sub bills, so you can cancel or haggle in time. that one's Pro. the ? up top reopens this any time."},
];
function tourSeen(){try{return localStorage.getItem('sg_tour_done')==='1';}catch{return false;}}
function tourMarkSeen(){try{localStorage.setItem('sg_tour_done','1');}catch{}}
let sgTourStep;
let sgTourOpener=null;
function startTour(){
  endTour();
  sgTourOpener=document.activeElement;
  sgTourStep=0;
  pushOverlayState();
  renderTourStep();
}
function endTour(fromHistory){
  if(sgTourStep===undefined)return;
  if(!fromHistory&&popOverlayState())return;
  sgTourStep=undefined;
  tourMarkSeen();
  const b=document.getElementById('tourbox');if(b)b.remove();
  const r=document.getElementById('tourring');if(r)r.remove();
  const o=sgTourOpener;sgTourOpener=null;
  if(o&&o!==document.body&&o.isConnected&&o.getClientRects().length)o.focus();
}
function renderTourStep(){
  const n=sgTourStep,stop=TOUR_STOPS[n];
  if(!stop)return endTour();
  const show=()=>{
    const ob=document.getElementById('tourbox');if(ob)ob.remove();
    const or=document.getElementById('tourring');if(or)or.remove();
    if(stop.sel){
      const el=document.querySelector(stop.sel);
      if(el){
        el.scrollIntoView({block:'center',behavior:'instant'});
        const r=el.getBoundingClientRect();
        const ring=document.createElement('div');
        ring.id='tourring';
        ring.style.cssText=`left:${r.left-6}px;top:${r.top-6}px;width:${r.width+12}px;height:${r.height+12}px;`;
        document.body.appendChild(ring);
      }
    }
    const last=n===TOUR_STOPS.length-1;
    const box=document.createElement('div');
    box.id='tourbox';
    box.setAttribute('role','dialog');
    box.setAttribute('aria-label','App tour');
    box.innerHTML=`<p>${esc(stop.text)}</p><div class="tourrow">`+
      `<span class="tourcount">${n===0?'':`${n} of ${TOUR_STOPS.length-1}`}</span>`+
      `<button type="button" class="tourbtn ghost" id="tour-skip">${last?'Done':n===0?'No thanks':'Skip'}</button>`+
      (last?'':`<button type="button" class="tourbtn" id="tour-next">${n===0?'Show me':'Next'}</button>`)+
      `</div>`;
    document.body.appendChild(box);
    document.getElementById('tour-skip').onclick=()=>endTour();
    const next=document.getElementById('tour-next');
    if(next){next.onclick=()=>{sgTourStep=n+1;renderTourStep();};next.focus();}
    else document.getElementById('tour-skip').focus();
  };
  // Switch to the stop's tab first; the highlight target renders with the tab.
  // goTab is called with fromHistory=true so the tour never stacks tab entries
  // on top of its own single overlay entry.
  if(stop.tab&&currentTab!==stop.tab){goTab(stop.tab,true);setTimeout(show,60);}
  else show();
}
// Offered once, and only to an account that has not buried anything yet.
function maybeOfferTour(){
  if(tourSeen())return;
  if(subs.length||deathRow.length){tourMarkSeen();return;}
  startTour();
}

// ===== CRYPT KEEPER =====
function keeperClick(){
  const line=KEEPER_LINES[Math.floor(Math.random()*KEEPER_LINES.length)];
  document.getElementById('speechBubble').innerHTML=line;
  reactKeeper('pleased');
  const wrap=document.querySelector('.character-wrap');
  const r=wrap.getBoundingClientRect();
  burst(r.left+r.width/2,r.top+80,8);
}
function reactKeeper(state){
  const el=document.getElementById('keeperSVG');
  el.setAttribute('class',`keeper-char state-${state}`);
  if(keeperAnimTimeout)clearTimeout(keeperAnimTimeout);
  keeperAnimTimeout=setTimeout(()=>{el.setAttribute('class','keeper-char state-idle');},1600);
}
function syncKeeper(){
  const ms=totalMonthlySavings();
  // Highest band whose min is reached. Matching min..max left cent gaps ($199.87 fell between 199 and 200) and showed the empty line.
  let line=KEEPER_PROGRESS_LINES[0].line;
  if(ms>0){line=KEEPER_PROGRESS_LINES[1].line;for(const l of KEEPER_PROGRESS_LINES){if(l.min>1&&ms>=l.min)line=l.line;}}
  document.getElementById('speechBubble').innerHTML=line;
  // Update savings bar
  const maxBar=500;
  const pct=Math.min(100,Math.round(ms/maxBar*100));
  document.getElementById('savingsFill').style.width=pct+'%';
  document.getElementById('savingsPct').textContent=fmt(ms)+'/mo';
  // Update eye color based on tier
  const tier=getTier(ms);
  let iris=tier.key==='reaper'?'var(--reaper)':tier.key==='undertaker'?'var(--lamp)':tier.key==='gravedigger'?'var(--primary)':tier.key==='mourner'?'var(--money)':'var(--accent)';
  document.getElementById('leftIris')?.setAttribute('fill',iris);
  document.getElementById('rightIris')?.setAttribute('fill',iris);
  // Update mouth
  const mouth=document.getElementById('mouthPath');
  if(mouth){if(ms>=200)mouth.setAttribute('d','M86 94Q100 108 114 94');else if(ms>=50)mouth.setAttribute('d','M88 96Q100 106 112 96');else mouth.setAttribute('d','M89 98Q100 104 111 98');}
}
function blink(){const lb=document.getElementById('leftBlink'),rb=document.getElementById('rightBlink');if(lb)lb.setAttribute('height','28');if(rb)rb.setAttribute('height','28');setTimeout(()=>{if(lb)lb.setAttribute('height','0');if(rb)rb.setAttribute('height','0');},110);}
function scheduleBlink(){setTimeout(()=>{blink();scheduleBlink();},1800+Math.random()*3500);}

// ===== PARTICLES =====
function burst(x,y,count=12){for(let i=0;i<count;i++){const angle=(i/count)*Math.PI*2+Math.random()*.5;const dist=50+Math.random()*70;const p=document.createElement('div');p.className='particle';p.style.cssText=`left:${x}px;top:${y}px;width:${3+Math.random()*6}px;height:${3+Math.random()*6}px;background:${PARTICLE_COLORS[Math.floor(Math.random()*PARTICLE_COLORS.length)]};--tx:${(Math.cos(angle)*dist).toFixed(1)}px;--ty:${(Math.sin(angle)*dist-20).toFixed(1)}px;--dur:${(.55+Math.random()*.5).toFixed(2)}s;--rot:${Math.floor(Math.random()*360)}deg;`;document.body.appendChild(p);setTimeout(()=>p.remove(),1200);}}
function flashScreen(color='rgba(110,219,168,0.15)'){const el=document.createElement('div');el.style.cssText=`position:fixed;inset:0;background:${color};pointer-events:none;z-index:990;animation:screen-flash .5s ease forwards;`;document.body.appendChild(el);setTimeout(()=>el.remove(),600);}

// ===== RENDER GRAVEYARD =====
// Tombstone art with accumulating age details by days buried:
// 180+ days (weathered) adds light moss patches; 365+ (legendary) adds cracks
// and an ivy vine on top of the moss. Static art, no animation.
function tombArt(days){
  const moss=days>=180
    ?'<ellipse cx="15" cy="69" rx="6.5" ry="3" fill="rgba(110,219,168,0.26)"/><ellipse cx="44" cy="70" rx="5" ry="2.4" fill="rgba(110,219,168,0.18)"/><ellipse cx="19" cy="20" rx="4" ry="2.2" fill="rgba(110,219,168,0.2)" transform="rotate(-28 19 20)"/>'
    :'';
  const cracks=days>=365
    ?'<path d="M43 9l-3 7 3 6-3 7" stroke="rgba(215,205,200,0.4)" stroke-width="1" fill="none" stroke-linecap="round"/><path d="M12 48l5 4-2 5" stroke="rgba(215,205,200,0.32)" stroke-width="1" fill="none" stroke-linecap="round"/>'
    :'';
  const ivy=days>=365
    ?'<path d="M11 71q-2-9 1-17t2-15" stroke="rgba(110,219,168,0.42)" stroke-width="1.3" fill="none" stroke-linecap="round"/><ellipse cx="12" cy="60" rx="2.6" ry="1.5" fill="rgba(110,219,168,0.45)" transform="rotate(-38 12 60)"/><ellipse cx="14" cy="50" rx="2.6" ry="1.5" fill="rgba(110,219,168,0.45)" transform="rotate(32 14 50)"/><ellipse cx="14" cy="40" rx="2.3" ry="1.4" fill="rgba(110,219,168,0.4)" transform="rotate(-30 14 40)"/>'
    :'';
  return '<svg viewBox="0 0 60 72" width="50" height="60" aria-hidden="true"><path d="M8 72V28c0-14 10-24 22-24s22 10 22 24v44" fill="rgba(255,107,87,0.09)" stroke="rgba(215,205,200,0.6)" stroke-width="3"/><path d="M8 72h44" stroke="rgba(215,205,200,0.4)" stroke-width="2.5"/><path d="M24 32h12" stroke="rgba(215,205,200,0.5)" stroke-width="2.5" stroke-linecap="round"/><path d="M30 26v12" stroke="rgba(215,205,200,0.5)" stroke-width="2.5" stroke-linecap="round"/>'+cracks+ivy+moss+'<ellipse cx="30" cy="68" rx="18" ry="4" fill="rgba(110,219,168,0.06)"/></svg>';
}
function renderGraveyard(){
  const el=document.getElementById('graveyard-content');
  if(!subs.length){el.innerHTML='<div class="empty-state">the graveyard is empty...<br><span style="font-size:.8rem;color:var(--muted)">Already canceled something? Give it a tombstone and watch your savings grow.</span><br><button class="btn btn-green" type="button" data-action="go-bury" style="margin-top:16px">Bury your first subscription</button></div>';return;}
  el.innerHTML='<div class="tomb-grid">'+subs.map((sub,i)=>{
    const s=calcSavings(sub),age=getTombstoneAge(s.daysDead),lt=calcLifetimeCost(sub);
    // Fresh graves haven't accrued anything yet — show the projection instead of a deflating $0.
    const savedBlock=(s.daysDead===0||Math.round(s.totalSaved)===0)
      ?`<div class="tomb-saved" style="font-size:.95rem;line-height:1.35">saves ${fmt(sub.monthly_cost)}</div><div class="tomb-saved-label">every month from now on</div>`
      :`<div class="tomb-saved">${fmtShort(s.totalSaved)}</div><div class="tomb-saved-label">saved since burial</div>`;
    return`<div class="tombstone ${age.cls}" style="animation:tombRise .4s ease ${i*.06}s both"><button class="tomb-delete" data-action="remove-sub" data-id="${esc(sub.id)}">&times;</button>${age.label?`<span class="tomb-age-badge" title="${age.tip}">${age.label}<span class="sr-only"> (${age.tip.toLowerCase()})</span></span>`:''}<div class="tomb-cross">${tombArt(s.daysDead)}</div><div class="tomb-name">${esc(sub.name)}</div><div class="tomb-cost">${fmt(sub.monthly_cost)}/mo${lt?' &middot; '+fmtShort(lt)+' total':''}</div>${savedBlock}<div class="tomb-days">${s.daysDead} days buried</div></div>`;
  }).join('')+'</div>';
}

// ===== RENDER DEATH ROW =====
function renderDeathRow(){
  const el=document.getElementById('deathrow-list');
  if(!deathRow.length){el.innerHTML='<div class="empty-state" style="padding:1.5rem">nothing on last rites yet.<br><span style="font-size:.75rem;opacity:.5">add subscriptions you\'re considering canceling</span></div>';return;}
  el.innerHTML=deathRow.map(item=>`<div class="dr-card"><div class="dr-name">${esc(item.name)}</div><div class="dr-cost">${fmt(item.monthly_cost)}/mo &middot; ${esc(item.category)}</div>${item.notes?`<div class="dr-notes">"${esc(item.notes)}"</div>`:''}<div class="dr-actions"><button class="btn btn-green btn-sm" data-action="execute-dr" data-id="${esc(item.id)}">Bury it</button><button class="btn btn-sm btn-danger" data-action="remove-dr" data-id="${esc(item.id)}">Remove</button></div></div>`).join('');
}

// ===== RENDER DASHBOARD =====
function renderDashboard(){
  const el=document.getElementById('dashboard-content'),ms=totalMonthlySavings(),ts=totalSaved(),tier=getTier(ms),annual=ms*12;
  const catTotals={};subs.forEach(s=>{catTotals[s.category]=(catTotals[s.category]||0)+s.monthly_cost;});
  const catEntries=Object.entries(catTotals).sort((a,b)=>b[1]-a[1]),catMax=catEntries.length?catEntries[0][1]:1;
  const catHtml=catEntries.map(([cat,amt])=>{const pct=Math.round(amt/catMax*100),label=CATEGORIES.find(c=>c.value===cat)?.label||cat;return`<div class="cat-bar-wrap"><div class="cat-bar-label"><span>${label}</span><span>${fmt(amt)}/mo</span></div><div class="cat-bar-track"><div class="cat-bar-fill" style="width:${pct}%;background:var(--money)"></div></div></div>`;}).join('');
  el.innerHTML=`<div class="tier-card"><div><div class="tier-label">${tier.label}</div><div class="tier-sub">Saving ${fmt(ms)}/month</div></div></div><div class="stats-grid"><div class="stat-card"><div class="stat-lbl">Total Saved</div><div class="stat-val green">${fmtShort(ts)}</div></div><div class="stat-card"><div class="stat-lbl">Monthly Rate</div><div class="stat-val green">${fmt(ms)}</div></div><div class="stat-card"><div class="stat-lbl">Annual</div><div class="stat-val amber">${fmtShort(annual)}</div></div><div class="stat-card"><div class="stat-lbl">Buried</div><div class="stat-val">${subs.length}</div></div></div>${catEntries.length?`<div class="sec-lbl">by category</div><div class="card">${catHtml}</div>`:''}${deathRow.length?`<div class="sec-lbl" style="margin-top:12px">last rites: pending burials</div><div class="card" style="border:1px solid rgba(242,180,90,0.35)"><div style="font-size:.95rem;color:var(--lamp);font-weight:700;margin-bottom:10px">Cancel all ${deathRow.length} and save <strong>${fmt(deathRow.reduce((s,d)=>s+d.monthly_cost,0))}/mo</strong> more</div>${deathRow.map(d=>`<div style="display:flex;justify-content:space-between;align-items:center;padding:.45rem .1rem;border-top:1px solid var(--card-border);font-size:.85rem"><span>${esc(d.name)}</span><span style="color:var(--lamp);font-weight:600">${fmt(d.monthly_cost)}/mo</span></div>`).join('')}<button class="btn btn-amber btn-sm" type="button" data-action="go-deathrow" style="margin-top:12px;width:100%">Review Last Rites &rarr;</button></div>`:''}`;
}

function renderDailyTip(){const doy=Math.floor((Date.now()-new Date(new Date().getFullYear(),0,0))/86400000);const n=GENERAL_NUDGES[doy%GENERAL_NUDGES.length];document.getElementById('daily-tip').innerHTML=`<div class="tip-card"><div class="tip-text">${n.text}</div><a class="tip-cta" href="${n.link}" target="_blank" rel="noopener">${n.cta} &rarr;</a>${isAff(n.link)?'<div class="tip-disc">affiliate link</div>':''}</div>`;}

// ===== BURY =====
// In-flight guard: a double-tap must not save twice.
async function burySub(){if(burySub.busy)return;burySub.busy=true;try{await burySubRun();}finally{burySub.busy=false;}}
async function burySubRun(){const name=document.getElementById('add-name').value.trim(),cost=parseFloat(document.getElementById('add-cost').value),cat=document.getElementById('add-cat').value,canceled=document.getElementById('add-cancelled').value,reason=document.getElementById('add-reason').value.trim();if(!name||isNaN(cost)||cost<=0||!canceled){showToast('Fill in name, cost, and date');return;}try{setSyncStatus('syncing');const sub=await api('/subscriptions','POST',{name,monthly_cost:cost,category:cat,cancelled_date:canceled,cancel_reason:reason||null});subs.push(sub);setSyncStatus('synced');['add-name','add-cost','add-cancelled','add-reason'].forEach(id=>document.getElementById(id).value='');document.getElementById('add-cancelled').value=todayStr();renderAll();goTab('graveyard');showToast(name+' has been buried');reactKeeper('pleased');const wrap=document.querySelector('.character-wrap');if(wrap){const r=wrap.getBoundingClientRect();burst(r.left+r.width/2,r.top+80,15);}checkMilestones(sub);}catch(err){if(err.paymentRequired||err.sessionEnded){setSyncStatus('synced');return;}setSyncStatus('error');showToast(err.message);}}
async function removeSub(id){if(!await showConfirm('dig up this grave?','its savings history goes with it.'))return;try{setSyncStatus('syncing');await api('/subscriptions/'+id,'DELETE');subs=subs.filter(s=>s.id!==id);setSyncStatus('synced');renderAll();showToast('Removed');}catch(err){if(err.sessionEnded)return;setSyncStatus('error');showToast(err.message);}}

// ===== DEATH ROW =====
// In-flight guard: a double-tap must not save twice.
async function addToDeathRow(){if(addToDeathRow.busy)return;addToDeathRow.busy=true;try{await addToDeathRowRun();}finally{addToDeathRow.busy=false;}}
async function addToDeathRowRun(){const name=document.getElementById('dr-name').value.trim(),cost=parseFloat(document.getElementById('dr-cost').value),cat=document.getElementById('dr-cat').value,notes=document.getElementById('dr-notes').value.trim();if(!name||isNaN(cost)||cost<=0){showToast('Fill in name and cost');return;}try{setSyncStatus('syncing');const item=await api('/death-row','POST',{name,monthly_cost:cost,category:cat,notes:notes||null});deathRow.push(item);setSyncStatus('synced');['dr-name','dr-cost','dr-notes'].forEach(id=>document.getElementById(id).value='');renderDeathRow();renderDashboard();showToast(name+' is on Last Rites');}catch(err){if(err.paymentRequired||err.sessionEnded){setSyncStatus('synced');return;}setSyncStatus('error');showToast(err.message);}}
async function removeDR(id){if(!await showConfirm('take it off last rites?','it leaves the list. nothing is canceled or buried.','take it off','keep it'))return;try{setSyncStatus('syncing');await api('/death-row/'+id,'DELETE');deathRow=deathRow.filter(d=>d.id!==id);setSyncStatus('synced');renderDeathRow();renderDashboard();}catch(err){if(err.sessionEnded)return;setSyncStatus('error');showToast(err.message);}}
async function executeDR(id){const item=deathRow.find(d=>d.id===id);if(!item)return;if(!confirm(`Bury ${item.name}?`))return;try{setSyncStatus('syncing');const sub=await api('/death-row/'+id+'/execute','POST',{cancelled_date:todayStr()});deathRow=deathRow.filter(d=>d.id!==id);subs.push(sub);setSyncStatus('synced');renderAll();goTab('graveyard');showToast(item.name+' is buried');reactKeeper('pleased');const wrap=document.querySelector('.character-wrap');if(wrap){const r=wrap.getBoundingClientRect();burst(r.left+r.width/2,r.top+80,15);}checkMilestones(sub);}catch(err){if(err.paymentRequired||err.sessionEnded){setSyncStatus('synced');return;}setSyncStatus('error');showToast(err.message);}}

// ===== MILESTONES & CELEBRATIONS =====
function checkMilestones(newSub){const ts=totalSaved();for(const m of MILESTONES){if(seenMilestones.includes(m.key))continue;const hit=m.check?m.check(subs):ts>=m.threshold;if(hit){seenMilestones.push(m.key);localStorage.setItem('sg_milestones',JSON.stringify(seenMilestones));celebrateFull(m.title,m.msg,newSub?.category);return;}}const tier=getTier(totalMonthlySavings()),msgs=CELEB_MSGS[tier.key],msg=msgs[Math.floor(Math.random()*msgs.length)];showCelebration(msg.title,msg.msg,newSub?.category);}
function showCelebration(title,msg,category,isMilestone){
  // Pick a creature — category-themed or random
  const catCreatures={streaming:'bat',software:'spider',fitness:'zombie',food:'skull',gaming:'ghost',music:'raven',audiobooks:'raven',storage:'spider',news:'cat',productivity:'skull',other:'ghost'};
  const creatureKey=category&&catCreatures[category]?catCreatures[category]:CREATURE_KEYS[Math.floor(Math.random()*CREATURE_KEYS.length)];
  document.getElementById('celeb-creature').innerHTML=CREATURES[creatureKey];
  document.getElementById('celeb-title').textContent=title;
  document.getElementById('celeb-msg').textContent=msg;
  const nudges=category&&CATEGORY_NUDGES[category]?CATEGORY_NUDGES[category]:GENERAL_NUDGES;
  const n=nudges[Math.floor(Math.random()*nudges.length)];
  document.getElementById('celeb-nudge').innerHTML=`<div class="tip-card" style="text-align:left;margin:12px 0"><div class="tip-text">${n.text}</div><a class="tip-cta" href="${n.link}" target="_blank" rel="noopener">${n.cta} &rarr;</a>${isAff(n.link)?'<div class="tip-disc">affiliate link</div>':''}</div>`;
  pushOverlayState();
  document.getElementById('celeb-overlay').style.display='flex';
  // Graduated celebration based on milestone vs normal
  if(isMilestone){fireConfetti();fireConfetti();} else{fireConfetti();}
}
function celebrateFull(title,msg,category){
  const el=document.getElementById('keeperSVG');el.setAttribute('class','keeper-char state-celebrating');
  flashScreen('rgba(255,107,87,0.12)');
  setTimeout(()=>flashScreen('rgba(110,219,168,0.15)'),300);
  setTimeout(()=>flashScreen('rgba(233,223,201,0.12)'),600);
  for(let w=0;w<6;w++){setTimeout(()=>{for(let i=0;i<15;i++)burst(window.innerWidth*(.05+Math.random()*.9),window.innerHeight*(.05+Math.random()*.8),10);},w*260);}
  setTimeout(()=>{el.setAttribute('class','keeper-char state-idle');},5000);
  showCelebration(title,msg,category,true);
}
function closeCeleb(fromHistory){if(!fromHistory&&popOverlayState())return;document.getElementById('celeb-overlay').style.display='none';}
function fireConfetti(){const canvas=document.getElementById('confetti-canvas'),ctx=canvas.getContext('2d');canvas.width=window.innerWidth;canvas.height=window.innerHeight;const particles=Array.from({length:80},()=>({x:canvas.width/2+(Math.random()-.5)*200,y:canvas.height/2,vx:(Math.random()-.5)*12,vy:Math.random()*-14-4,size:Math.random()*6+3,color:PARTICLE_COLORS[Math.floor(Math.random()*PARTICLE_COLORS.length)],rotation:Math.random()*360,rv:(Math.random()-.5)*8,life:1}));let frame=0;function animate(){ctx.clearRect(0,0,canvas.width,canvas.height);let alive=false;for(const p of particles){if(p.life<=0)continue;alive=true;p.x+=p.vx;p.y+=p.vy;p.vy+=.3;p.vx*=.99;p.rotation+=p.rv;p.life-=.008;ctx.save();ctx.translate(p.x,p.y);ctx.rotate(p.rotation*Math.PI/180);ctx.globalAlpha=p.life;ctx.fillStyle=p.color;ctx.fillRect(-p.size/2,-p.size/2,p.size,p.size*.6);ctx.restore();}if(alive&&frame<200){frame++;requestAnimationFrame(animate);}else ctx.clearRect(0,0,canvas.width,canvas.height);}requestAnimationFrame(animate);}
function closeDeleteModal(fromHistory){const pw=document.getElementById('delete-pw');if(pw)pw.value='';const ct=document.getElementById('delete-confirm-text');if(ct)ct.value='';const err=document.getElementById('delete-err');if(err){err.textContent='';err.style.display='none';}if(!fromHistory&&popOverlayState())return;const m=document.getElementById('delete-modal');if(m)m.style.display='none';}
async function confirmDeleteAccount(){const err=document.getElementById('delete-err');let body;if(deleteViaHub){const typed=document.getElementById('delete-confirm-text').value.trim();if(typed!=='DELETE'){err.textContent='Type DELETE to confirm.';err.style.display='block';return;}{const cur=localStorage.getItem('hub_pro_jwt');if(cur&&hubTokenExpiringSoon(cur))await refreshHubPro();}const hubJwt=localStorage.getItem('hub_pro_jwt');if(!hubJwt){err.textContent="There's no App Hub sign-in on this device. Open the App Hub, launch Subscription Graveyard from there, then try again. Or use Forgot password on the sign-in screen to set a password.";err.style.display='block';return;}body={hub_pro_jwt:hubJwt,confirm:'DELETE'};}else{const pw=document.getElementById('delete-pw').value;if(!pw||pw.length<10){err.textContent='Enter your current password (min 10 chars)';err.style.display='block';return;}body={current_password:pw};}try{await api('/auth/account','DELETE',body);closeDeleteModal(true);localStorage.clear();showToast('Account deleted');setTimeout(()=>location.reload(),1000);}catch(e){err.textContent=e.message;err.style.display='block';}}
async function exportMyData(){try{setSyncStatus('syncing');const data=await api('/account/export');setSyncStatus('synced');const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='subscription-graveyard-export-'+new Date().toISOString().slice(0,10)+'.json';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),0);showToast('Data exported');}catch(e){if(e.sessionEnded)return;setSyncStatus('error');showToast(e.message);}}

// ===== PRO STATUS =====
let isPro=false;
// Starts false so nothing sells Pro before /api/pro-status answers. It turns true
// only when this copy has a Pro hub connected (pro_available:true).
let proAvailable=false;
// From the server's UPGRADE_URL and PRO_PRICE_TEXT settings (only sent when a hub is connected).
// No upgrade URL = Go Pro is hidden. No price text = no price line.
let proUpgradeUrl='';
let proPriceText='';
function applyProAvail(){
  document.querySelectorAll('[data-pro-on]').forEach(el=>{el.hidden=!proAvailable;});
  document.querySelectorAll('[data-pro-off]').forEach(el=>{el.hidden=proAvailable;});
  const b=document.getElementById('unlock-pro-btn');
  if(b){b.href=proAvailable?(proUpgradeUrl||'#'):'https://subscriptiongraveyard.app';if(proAvailable&&!proUpgradeUrl)b.style.display='none';}
  const price=document.getElementById('pro-required-price');
  if(price){price.textContent=proPriceText;price.hidden=!(proAvailable&&proPriceText);}
  const cta=document.getElementById('pro-required-cta');
  if(cta)cta.hidden=proAvailable&&!proUpgradeUrl;
}
// With no Pro hub, Go Pro opens the popup that explains Pro lives on the hosted version.
document.addEventListener('click',e=>{const b=e.target.closest&&e.target.closest('#unlock-pro-btn');if(b&&!proAvailable){e.preventDefault();showProRequired();}});
async function hydrateProStatus(){
  try{
    const data=await api('/pro-status');
    const proRegion=document.getElementById('pro-badge-region');
    const unlockBtn=document.getElementById('unlock-pro-btn');
    isPro=!!data.is_pro;
    proAvailable=data.pro_available===true;
    proUpgradeUrl=(proAvailable&&typeof data.upgrade_url==='string'&&/^https?:\/\//i.test(data.upgrade_url))?data.upgrade_url:'';
    proPriceText=(proAvailable&&typeof data.pro_price_text==='string')?data.pro_price_text:'';
    applyProAvail();
    // Feedback button only when FEEDBACK_WEBHOOK_URL is set on the server.
    if(data.feedback_available===true)loadFeedbackWidget();
    if(isPro){
      proPaused=false;
      if(proRegion)proRegion.classList.add('show');
      if(unlockBtn)unlockBtn.style.display='none';
      if(data.pro_until){
        const until=new Date(data.pro_until).toLocaleDateString();
        const ut=document.getElementById('pro-until-text');
        if(ut)ut.textContent='through '+until;
      }
      document.querySelectorAll('.locked-feature').forEach(el=>el.classList.remove('locked-feature'));
      loadWatchlist();
    }else{
      if(proRegion)proRegion.classList.remove('show');
      if(unlockBtn)unlockBtn.style.display=(proAvailable&&!proUpgradeUrl)?'none':'inline-block';
    }
  }catch(e){console.error('Pro hydrate failed:',e);}
}

// ===== WATCHLIST =====
function openWatchlistOrUpgrade(){
  const tabBtn=document.querySelector('[data-tab="watchlist"]');
  if(tabBtn&&tabBtn.classList.contains('locked-feature')){
    showProRequired('renewal-watchlist');
    return;
  }
  goTab('watchlist');
  loadWatchlist();
}
async function loadWatchlist(){
  const list=document.getElementById('watchlist-items');
  if(!list)return;
  try{
    const data=await api('/watchlist');
    const items=data.items||[];
    list.innerHTML=items.length?items.map(it=>{
      const cyc=it.billing_cycle&&it.billing_cycle!=='monthly'?` &middot; ${esc(it.billing_cycle)}`:'';
      const negotiate=it.reminder_mode==='negotiate';
      const badge=negotiate?` <span class="wl-badge-negotiate">negotiation target</span>`:'';
      const scriptLink=negotiate?` &middot; <a data-action="show-negotiation-script" data-name="${esc(it.name)}" data-date="${esc(it.next_renewal_date)}" style="color:var(--accent,#E9DFC9);cursor:pointer">the script</a>`:'';
      return `<div class="wl-card"><div><div class="wl-name">${esc(it.name)}${badge}</div><div class="wl-meta">${fmt(it.monthly_cost)}/mo${cyc} &middot; renews ${esc(it.next_renewal_date)}${it.cancel_url?` &middot; <a href="${esc(it.cancel_url)}" target="_blank" rel="noopener" style="color:var(--lamp)">cancel link</a>`:''}${scriptLink}</div></div><button class="wl-del" data-action="delete-watchlist" data-id="${esc(it.id)}" title="Remove">&times;</button></div>`;
    }).join(''):'<div class="empty-state" style="padding:1.5rem">no items yet.<br><span style="font-size:.75rem;opacity:.5">add a subscription above to start getting renewal warnings.</span></div>';
  }catch(err){
    if(err.message&&/402|pro|upgrade/i.test(err.message)){
      list.innerHTML='<div class="empty-state" style="padding:1.5rem">watchlist requires Pro.</div>';
    }else{
      list.innerHTML='<div class="empty-state" style="padding:1.5rem">could not load watchlist.</div>';
      console.error('loadWatchlist:',err);
    }
  }
}
async function addWatchlistItem(formData){
  const body={
    name:formData.get('name'),
    monthly_cost:parseFloat(formData.get('monthly_cost')),
    next_renewal_date:formData.get('next_renewal_date'),
    cancel_url:formData.get('cancel_url')||null,
    billing_cycle:formData.get('billing_cycle')||'monthly',
    reminder_mode:formData.get('reminder_mode')||'cancel',
  };
  if(!body.name||isNaN(body.monthly_cost)||body.monthly_cost<=0||!body.next_renewal_date){showToast('Fill in name, cost, and renewal date');return;}
  try{
    setSyncStatus('syncing');
    await api('/watchlist','POST',body);
    setSyncStatus('synced');
    const form=document.getElementById('watchlist-form');
    if(form)form.reset();
    loadWatchlist();
    showToast(body.name+' added to watchlist');
  }catch(err){if(err.paymentRequired||err.sessionEnded){setSyncStatus('synced');return;}setSyncStatus('error');showToast(err.message);}
}
async function deleteWatchlistItem(id){
  if(!confirm('Remove from watchlist?'))return;
  try{
    setSyncStatus('syncing');
    await api('/watchlist','DELETE',{id});
    setSyncStatus('synced');
    loadWatchlist();
  }catch(err){if(err.sessionEnded)return;setSyncStatus('error');showToast(err.message);}
}

// ===== EVENT WIRING (replaces inline onclick / onsubmit) =====
function wireStaticHandlers(){
  // Landing view is always 'login' (static HTML default) — replaceState so
  // the very first Back leaves the site. If a stored session logs the user
  // in moments later, showApp()'s own replaceState overwrites this.
  // Logged-out landing is the guest sample burial, not a sign-up wall (UX
  // fixes 2026-11). A refresh on the log-in or sign-up card stays there.
  if(BOOT_AUTH==='login'||BOOT_AUTH==='signup')landAuth(BOOT_AUTH);
  else{
    // Reading it re-validates it, which also purges an expired or edited one.
    const pending=readGuestSub();
    showGuest(BOOT_GUEST==='try'||!pending?'try':'result',{replace:true});
  }
  const guestForm=document.getElementById('guest-form');
  if(guestForm){guestForm.addEventListener('submit',guestBury);guestForm.addEventListener('input',saveGuestDraft);}
  const obBuryBtn=document.getElementById('ob-bury-btn');
  if(obBuryBtn)obBuryBtn.addEventListener('click',obBury);
  // Auth tabs
  document.querySelectorAll('.auth-tab').forEach((btn,i)=>{
    btn.addEventListener('click',()=>authTab(i===0?'login':'signup'));
  });
  // Auth form
  const authForm=document.getElementById('auth-form');
  if(authForm)authForm.addEventListener('submit',authSubmit);
  // Forgot password
  const forgotBtn=document.getElementById('auth-forgot-btn');
  if(forgotBtn)forgotBtn.addEventListener('click',forgotPw);
  // Email verification (6-digit code)
  const verifyBtn=document.getElementById('verify-code-btn');
  if(verifyBtn)verifyBtn.addEventListener('click',submitVerifyCode);
  const verifyResendBtn=document.getElementById('verify-resend-btn');
  if(verifyResendBtn)verifyResendBtn.addEventListener('click',()=>resendVerify(pendingVerifyEmail||document.getElementById('auth-email').value.trim()));
  const verifyInput=document.getElementById('verify-code-input');
  if(verifyInput)verifyInput.addEventListener('keydown',(e)=>{if(e.key==='Enter'){e.preventDefault();submitVerifyCode();}});
  const verifyPwInput=document.getElementById('verify-pw-input');
  if(verifyPwInput)verifyPwInput.addEventListener('keydown',(e)=>{if(e.key==='Enter'){e.preventDefault();submitVerifyCode();}});
  // (Privacy link in auth screen uses delegated [data-action="show-privacy"] handler)
  // Reset password
  const resetBtn=document.getElementById('reset-confirm-btn');
  if(resetBtn)resetBtn.addEventListener('click',confirmReset);
  // Header buttons
  const helpBtn=document.getElementById('hdr-help');
  if(helpBtn)helpBtn.addEventListener('click',()=>openHelp());
  // Retry on the load-failure banner
  const retryBtn=document.getElementById('load-retry-btn');
  if(retryBtn)retryBtn.addEventListener('click',()=>loadAppData());
  const hdrLogout=document.getElementById('hdr-logout-btn');
  if(hdrLogout)hdrLogout.addEventListener('click',logout);
  // Keeper character
  const keeperWrap=document.querySelector('.character-wrap');
  if(keeperWrap)keeperWrap.addEventListener('click',keeperClick);
  // Tabs
  document.querySelectorAll('.tabs .tab').forEach(btn=>{
    const tab=btn.dataset.tab;
    btn.addEventListener('click',()=>{
      // Hide the hover tooltip after a click so it doesn't linger over the panel
      btn.classList.add('tt-off');
      if(tab==='watchlist'){openWatchlistOrUpgrade();}else{goTab(tab);}
    });
    btn.addEventListener('mouseleave',()=>btn.classList.remove('tt-off'));
  });
  // Death Row add
  const drAddBtn=document.getElementById('dr-add-btn');
  if(drAddBtn)drAddBtn.addEventListener('click',addToDeathRow);
  // Bury submit
  const burySubBtn=document.getElementById('bury-sub-btn');
  if(burySubBtn)burySubBtn.addEventListener('click',burySub);
  // Watchlist form
  const wlForm=document.getElementById('watchlist-form');
  if(wlForm)wlForm.addEventListener('submit',(e)=>{e.preventDefault();addWatchlistItem(new FormData(wlForm));});
  // Onboarding close
  const onboardBtn=document.getElementById('onboard-start-btn');
  if(onboardBtn)onboardBtn.addEventListener('click',()=>closeOnboard());
  // Celebration overlay backdrop close + stop propagation on box
  const celebOverlay=document.getElementById('celeb-overlay');
  if(celebOverlay)celebOverlay.addEventListener('click',(e)=>{
    if(e.target===celebOverlay)closeCeleb();
  });
  const celebCloseBtn=document.querySelector('.celeb-close');
  if(celebCloseBtn)celebCloseBtn.addEventListener('click',()=>closeCeleb());
  // Privacy modal close button
  const privacyCloseBtn=document.getElementById('privacy-close-btn');
  if(privacyCloseBtn)privacyCloseBtn.addEventListener('click',()=>hidePrivacy());
  // Styled confirm modal
  const confirmOkBtn=document.getElementById('confirm-ok-btn');
  if(confirmOkBtn)confirmOkBtn.addEventListener('click',()=>resolveConfirm(true));
  const confirmCancelBtn=document.getElementById('confirm-cancel-btn');
  if(confirmCancelBtn)confirmCancelBtn.addEventListener('click',()=>resolveConfirm(false));
  const confirmModal=document.getElementById('confirm-modal');
  if(confirmModal)confirmModal.addEventListener('click',(e)=>{if(e.target===confirmModal)resolveConfirm(false);});
  // Delete modal
  const deleteCancelBtn=document.getElementById('delete-cancel-btn');
  if(deleteCancelBtn)deleteCancelBtn.addEventListener('click',()=>closeDeleteModal());
  const deleteConfirmBtn=document.getElementById('delete-confirm-btn');
  if(deleteConfirmBtn)deleteConfirmBtn.addEventListener('click',confirmDeleteAccount);
  const deleteUseHubBtn=document.getElementById('delete-use-hub-btn');
  if(deleteUseHubBtn)deleteUseHubBtn.addEventListener('click',()=>setDeleteMode(true));
  const deleteUsePwBtn=document.getElementById('delete-use-pw-btn');
  if(deleteUsePwBtn)deleteUsePwBtn.addEventListener('click',()=>setDeleteMode(false));
  // Change-password modal
  const pwForm=document.getElementById('password-form');
  if(pwForm)pwForm.addEventListener('submit',savePassword);
  const pwCancel=document.getElementById('pw-cancel-btn');
  if(pwCancel)pwCancel.addEventListener('click',()=>closePasswordModal());
}

// Tab bar scroll hint: right-edge fade while more tabs sit off-screen (mobile).
function wireTabScrollHint(){
  const tabs=document.querySelector('.tabs');
  const wrap=document.querySelector('.tabs-wrap');
  if(!tabs||!wrap)return;
  const update=()=>{wrap.classList.toggle('scroll-more',tabs.scrollWidth-tabs.clientWidth-tabs.scrollLeft>4);};
  tabs.addEventListener('scroll',update,{passive:true});
  window.addEventListener('resize',update);
  // The tab bar is hidden (0px wide) until login, so recompute when its size
  // changes — this fires when #app-outer becomes visible.
  if(window.ResizeObserver)new ResizeObserver(update).observe(tabs);
  update();
}

// Esc closes ONE layer, topmost first (a Back press means "leave what I
// opened" and closes them all — see closeAllOverlays). Ordered by z-index, so
// with two stacked overlays Escape peels the one the user is actually looking
// at. Each closer runs with fromHistory falsy, so Escape goes through
// history.back() exactly like the on-screen close button.
const ESC_CLOSERS=[
  ['help-modal',closeHelp],
  ['pro-required-modal',closeProRequired],
  ['confirm-modal',(fh)=>resolveConfirm(false,fh)],
  ['negotiate-modal',closeNegotiate],
  ['delete-modal',closeDeleteModal],
  ['password-modal',closePasswordModal],
  ['privacy-modal',hidePrivacy],
  ['celeb-overlay',closeCeleb],
  ['onboard-overlay',closeOnboard],
];
function wireEscapeKey(){
  document.addEventListener('keydown',(e)=>{
    if(e.key!=='Escape')return;
    // The tour is a plain box, not a styled overlay: check it by presence.
    if(document.getElementById('tourbox')){endTour();return;}
    for(const [id,close] of ESC_CLOSERS){
      const el=document.getElementById(id);
      if(el&&el.style.display==='flex'){close();return;}
    }
  });
}

// ===== DIALOG FOCUS =====
// When a dialog opens, focus moves into it, Tab and Shift+Tab stay inside it,
// and when it closes focus goes back to whatever opened it. Escape is handled
// by wireEscapeKey above. Every overlay here is shown and hidden through its
// style.display, so one observer per overlay catches every open and close path
// (buttons, Escape, Back) without touching each open/close function.
const FOCUSABLE_SEL='a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
function focusablesIn(el){return [...el.querySelectorAll(FOCUSABLE_SEL)].filter(n=>n.getClientRects().length>0);}
function isShown(el){return !!(el&&el.style.display&&el.style.display!=='none');}
// Last element focused outside the open dialog. Some openers move focus into
// the dialog themselves (help panel), so by the time the observer runs the
// active element is already inside; this remembers the real opener.
let lastFocusOutside=null;
document.addEventListener('focusin',(e)=>{const d=topOpenDialog();if(!d||!d.contains(e.target))lastFocusOutside=e.target;},true);
function trapFocus(el,opener){
  if(!opener||el.contains(opener))opener=lastFocusOutside;
  el._sgOpener=opener&&opener!==document.body&&!el.contains(opener)?opener:null;
  if(el.contains(document.activeElement))return;
  const f=focusablesIn(el);
  if(f.length)f[0].focus();
  else{if(!el.hasAttribute('tabindex'))el.setAttribute('tabindex','-1');el.focus();}
}
function releaseFocus(el){
  const o=el._sgOpener;el._sgOpener=null;
  if(o&&o.isConnected&&o.getClientRects().length)o.focus();
}
function topOpenDialog(){
  const tb=document.getElementById('tourbox');if(tb)return tb;
  for(const [id] of ESC_CLOSERS){const el=document.getElementById(id);if(isShown(el))return el;}
  return null;
}
function wireDialogFocus(){
  for(const [id] of ESC_CLOSERS){
    const el=document.getElementById(id);
    if(!el)continue;
    let open=isShown(el);
    new MutationObserver(()=>{
      const now=isShown(el);
      if(now===open)return;
      open=now;
      if(now)trapFocus(el,document.activeElement);else releaseFocus(el);
    }).observe(el,{attributes:true,attributeFilter:['style']});
  }
  document.addEventListener('keydown',(e)=>{
    if(e.key!=='Tab')return;
    const d=topOpenDialog();
    if(!d)return;
    const f=focusablesIn(d);
    if(!f.length){e.preventDefault();return;}
    const first=f[0],last=f[f.length-1],a=document.activeElement;
    if(e.shiftKey&&(a===first||!d.contains(a))){e.preventDefault();last.focus();}
    else if(!e.shiftKey&&(a===last||!d.contains(a))){e.preventDefault();first.focus();}
  });
}

// ── BROWSER BACK/FORWARD ─────────────────────────────────────────────────
// Closes every open modal/panel (a Back press means "leave what I opened,"
// not "close one layer" the way Escape does), then restores whichever view
// the popped history entry points at.
// Every call passes fromHistory=true — this runs FROM popstate, so the entry
// is already consumed and re-entering history.back() would loop.
function closeAllOverlays(){
  const isOpen=(id)=>{const el=document.getElementById(id);return !!(el&&el.style.display&&el.style.display!=='none');};
  if(document.getElementById('tourbox'))endTour(true);
  if(isOpen('help-modal'))closeHelp(true);
  if(isOpen('pro-required-modal'))closeProRequired(true);
  if(isOpen('privacy-modal'))hidePrivacy(true);
  if(isOpen('delete-modal'))closeDeleteModal(true);
  if(isOpen('password-modal'))closePasswordModal(true);
  if(isOpen('confirm-modal'))resolveConfirm(false,true);
  if(isOpen('negotiate-modal'))closeNegotiate(true);
  if(isOpen('celeb-overlay'))closeCeleb(true);
  if(isOpen('onboard-overlay'))closeOnboard(true);
}
// Restores a pre-auth history entry (login/signup tab, or the verify-code
// box). Always resets from a clean baseline first, since the popped entry
// can be several steps away from the screen's current DOM state.
function restoreAuthView(state){
  if(state&&(state.guestView==='try'||state.guestView==='result')){showGuest(state.guestView,{fromHistory:true});return;}
  const view=(state&&state.authView)||'login';
  const mode=state&&state.mode==='signup'?'signup':'login';
  hideVerify();
  authTab(mode,true);
  if(view==='verify')showVerify((state&&state.email)||pendingVerifyEmail||'',true);
}
function wireBackButton(){
  window.addEventListener('popstate',(ev)=>{
    closeAllOverlays();
    const state=ev.state||{};
    if(currentUser){
      // Authenticated: restore the in-app tab. A stale pre-auth entry (no
      // `view` — e.g. left over from before login, or from before logout
      // replaceState()'d a clean landing) defaults to the graveyard landing.
      const tab=state.view||'graveyard';
      goTab(tab,true);
      // watchlist's list is normally (re)loaded by the click handler
      // (openWatchlistOrUpgrade); a popstate restore bypasses that path, so
      // load it explicitly here too.
      if(tab==='watchlist')loadWatchlist();
    }else{
      // Not authenticated (including just after logout): restore the
      // auth-screen step. A stale in-app tab entry (no `authView`) defaults
      // to the login landing.
      restoreAuthView(state);
    }
  });
}

// Delegated handler for dynamically-rendered buttons that previously used inline onclick.
function wireDelegatedHandlers(){
  document.addEventListener('click',(e)=>{
    const target=e.target.closest('[data-action]');
    if(!target)return;
    const action=target.dataset.action;
    const id=target.dataset.id;
    switch(action){
      case 'remove-sub':removeSub(id);break;
      case 'execute-dr':executeDR(id);break;
      case 'remove-dr':removeDR(id);break;
      case 'delete-watchlist':deleteWatchlistItem(id);break;
      case 'show-negotiation-script':showNegotiationScript(target.dataset.name,target.dataset.date);break;
      case 'close-negotiate-modal':closeNegotiate();break;
      case 'export-data':exportMyData();break;
      case 'open-delete-modal':openDeleteModal();break;
      case 'open-password-modal':openPasswordModal();break;
      case 'show-privacy':showPrivacy();break;
      case 'close-help':closeHelp();break;
      case 'start-tour':closeHelp();setTimeout(startTour,220);break;
      case 'tip-act':runTipAction(target.dataset.tipAct);break;
      case 'go-bury':goTab('add');break;
      case 'go-deathrow':goTab('deathrow');break;
      case 'guest-login':leaveGuestTo('login');break;
      case 'guest-signup':leaveGuestTo('signup');break;
      case 'guest-redo':showGuest('try');break;
      case 'guest-try':showGuest('try');break;
      case 'ob-chip':toggleObChip(target.dataset.k);break;
    }
  });
}

// ===== INIT =====
(async function init(){
  wireStaticHandlers();
  wireDelegatedHandlers();
  wireEscapeKey();
  wireDialogFocus();
  wireBackButton();
  wireTabScrollHint();
  checkResetToken();
  try{
  // Refresh a stale hub Pro token before anything uses it (hub-sso, pro-status).
  // valid:true → fresh token stored; valid:false → removed (free); network
  // error → keep whatever we have and behave as before.
  const storedHub=localStorage.getItem('hub_pro_jwt');
  if(storedHub&&hubTokenExpiringSoon(storedHub)){
    const hadPro=hubTokenHasPro(storedHub);
    const refreshed=await refreshHubPro();
    // Only an unreachable hub is "paused". valid:false means the Pro ended.
    if(refreshed===null&&hadPro)showProPaused();
  }
  // Who is signed in? One GET /api/me (the cookie is HttpOnly). A fresh
  // ?hubpro= arrival skips it: hub-sso below decides who this is.
  let bootErr=null;
  if(!HUB_ARRIVAL&&!window._resetToken){
    // Pre-cookie builds kept the login token in localStorage. It's dead
    // now (the server only reads the cookie), so just wipe any leftover.
    try{localStorage.removeItem('sg_token');}catch(e){}
    try{currentUser=await api('/me');}
    catch(err){if(!err.sessionEnded)bootErr=err.message;}
  }
  // Hub SSO: if we landed here with a hub Pro JWT and no session, exchange it.
  if(!currentUser&&!bootErr){
    const hubPro=localStorage.getItem('hub_pro_jwt');
    if(hubPro){
      try{
        const d=await api('/auth/hub-sso','POST',{hub_pro_jwt:hubPro});
        currentUser=d.user;
      }catch(err){console.error('hub-sso:',err.message);}
    }
  }
  // A /reset/<token> link owns the page: checkResetToken() already hid the
  // auth screen, and re-showing it here stacked a second main landmark under
  // the reset form and covered its controls.
  if(window._resetToken){/* reset screen is up */}
  // Whatever happened above, nobody gets stranded on the boot screen. No session
  // means the auth screen, and this is the only path that reveals it on a cold load.
  else if(currentUser){showApp();}else{showAuthScreen();if(bootErr)showAuthErr(bootErr);}
  }finally{
    // A thrown handler must not strand anyone on the boot screen. If it is still
    // up by now, no session resolved, which means the auth screen.
    const boot=document.getElementById('boot-screen');
    if(boot&&boot.style.display!=='none')showAuthScreen();
  }
  document.getElementById('add-cancelled').value=todayStr();
})();

// Expose FEEDBACK app name (was previously a separate inline <script>)
window.FEEDBACK_APP='Subscription Graveyard';

// ── Show/hide password toggle (uniform across the hub + all 5 apps) ─────────
(function initPwEyes(){
  var EYE='<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>';
  var EYEOFF='<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
  ['auth-pw','auth-pw2'].forEach(function(id){
    var input=document.getElementById(id);
    if(!input||input.dataset.eyeInit)return;
    input.dataset.eyeInit='1';
    var wrap=document.createElement('div');
    wrap.style.position='relative';
    input.parentNode.insertBefore(wrap,input);
    wrap.appendChild(input);
    input.style.paddingRight='40px';
    var btn=document.createElement('button');
    btn.type='button';
    btn.setAttribute('aria-label','Show password');
    btn.setAttribute('aria-pressed','false');
    btn.style.cssText='position:absolute;right:4px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;padding:8px;line-height:0;color:inherit;opacity:.55';
    btn.innerHTML=EYE;
    btn.addEventListener('click',function(){
      var show=input.type==='password';
      input.type=show?'text':'password';
      btn.innerHTML=show?EYEOFF:EYE;
      btn.setAttribute('aria-label',show?'Hide password':'Show password');
      btn.setAttribute('aria-pressed',String(show));
      input.focus();
    });
    wrap.appendChild(btn);
  });
})();
