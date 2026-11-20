// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// Security regression scanner. Runs as a pre-deploy gate.
// Each time a security audit surfaces a finding, we add a check here so the
// same thing can't silently regress in a future change.
//
// Run: node scripts/test-security.mjs
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '..');

function listFiles(dir, exts, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith('.')) continue;
    const full = join(dir, entry);
    const s = statSync(full);
    if (s.isDirectory()) {
      if (['vendor','node_modules','.wrangler','dist','build'].includes(entry)) continue;
      listFiles(full, exts, out);
    } else if (exts.some(e => entry.endsWith(e))) {
      out.push(full);
    }
  }
  return out;
}

const findings = [];
function flag(severity, file, line, rule, detail) {
  findings.push({ severity, file: relative(repoRoot, file), line, rule, detail });
}

// ── Source code checks (src/) ──────────────────────────────────────────────
const srcFiles = listFiles(join(repoRoot, 'src'), ['.js']);

for (const f of srcFiles) {
  const content = readFileSync(f, 'utf8');
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    const ln = idx + 1;

    // CORS wildcard.
    if (/Access-Control-Allow-Origin['"\s:,]+\*/.test(line)) {
      flag('HIGH', f, ln, 'CORS wildcard', 'Origin allowlist required. Never `*`.');
    }

    // Hardcoded secret patterns.
    if (/sk-ant-api03-[A-Za-z0-9_-]{20,}/.test(line)) flag('HIGH', f, ln, 'hardcoded ANTHROPIC key', 'Move to wrangler secret.');
    if (/\bre_[A-Za-z0-9]{20,}/.test(line))            flag('HIGH', f, ln, 'hardcoded RESEND key', 'Move to wrangler secret.');
    if (/sk_live_[A-Za-z0-9]{20,}/.test(line))         flag('HIGH', f, ln, 'hardcoded STRIPE live key', 'Move to wrangler secret.');
    if (/sk-[A-Za-z0-9]{40,}/.test(line) && !/sk-ant/.test(line)) flag('HIGH', f, ln, 'hardcoded OpenAI-shaped key', 'Move to wrangler secret.');
    if (/xox[baprs]-[A-Za-z0-9-]{20,}/.test(line))     flag('HIGH', f, ln, 'hardcoded Slack token', 'Move to secret store.');
    if (/AIza[A-Za-z0-9_-]{30,}/.test(line))           flag('HIGH', f, ln, 'hardcoded Google API key', 'Move to secret store.');
    if (/ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}/.test(line)) flag('HIGH', f, ln, 'hardcoded GitHub PAT', 'Move to secret store.');

    // PII / secrets in console logs.
    if (/console\.(log|error|warn|info|debug)\s*\([^)]*\b(password|passwordHash|pw_hash|token|jwt|apiKey|api_key|secret|authorization|req\.body|request\.body)\b/i.test(line)) {
      if (!/['"]\s*[^'"]*(password|token|secret|api[_-]?key)[^'"]*['"]\s*\)/i.test(line)) {
        flag('MEDIUM', f, ln, 'PII / secret in console log', 'Log identifier (user_id, request_id) — never the data.');
      }
    }

    // Sensitive data in localStorage / sessionStorage.
    if (/(localStorage|sessionStorage)\.setItem\s*\(\s*['"`][^'"`]*(password|secret|apiKey|api_key|credit|card|ssn)/i.test(line)) {
      flag('HIGH', f, ln, 'sensitive data in browser storage', 'Use HttpOnly cookies for auth; never localStorage.');
    }
  });

  // Module-level mutable CORS state (was Finding 9 of the original audit).
  if (/^\s*let\s+_corsHeaders\s*=/m.test(content)) {
    flag('HIGH', f, 0, 'module-level CORS state', 'Pass cors per-request — concurrent requests in same isolate race.');
  }

  // Password min length must be 10 (not 6). Catches regressions that lower the bar.
  const sixCharPw = content.match(/password\.length\s*<\s*6\b/);
  if (sixCharPw) {
    flag('HIGH', f, 0, 'password min < 10', 'Passwords need min 10 / max 200. 6-char minimum is too weak + PBKDF2 DoS risk.');
  }

  // signup must not return 409 on existing email (account enumeration).
  if (/account with this email already exists/i.test(content)) {
    flag('HIGH', f, 0, 'signup enumeration', 'Return identical shape regardless of email-exists.');
  }

  // Every JSON body must go through readJson() or carry a .catch: a bare
  // `await request.json()` turns a malformed body into a 500, which also
  // fires the 5xx alert beacon.
  lines.forEach((line, idx) => {
    if (/await\s+request\.json\(\)(?!\s*\.catch)/.test(line) && !/readJson/.test(line)) {
      flag('HIGH', f, idx + 1, 'bare request.json()', 'Use readJson(request) and answer 400 when it returns null.');
    }
  });

  // Signup on an existing UNVERIFIED row must take over the credentials and
  // resend the code. Leaving the squatter's password in place is a pre-hijack
  // account takeover.
  const signupMatch = content.match(/async\s+function\s+signup\s*\([^)]*\)\s*\{([\s\S]{0,2500})/);
  if (signupMatch && !/email_verified/.test(signupMatch[1])) {
    flag('HIGH', f, 0, 'signup ignores unverified rows', 'An unverified existing row must get the new password_hash, a token_version bump, and a fresh code.');
  }

  // hub-sso marking a pre-registered row verified must also replace its
  // password_hash (the squatter never proved ownership) and bump token_version.
  const ssoMatch = content.match(/async\s+function\s+hubSso\s*\([^)]*\)\s*\{([\s\S]{0,3500})/);
  if (ssoMatch && /email_verified=1/.test(ssoMatch[1]) && !/password_hash=\?/.test(ssoMatch[1])) {
    flag('HIGH', f, 0, 'hub-sso verifies a row without evicting the squatter', 'Set password_hash to a sentinel and bump token_version when verifying an existing row.');
  }

  // verifyJWT must require a numeric exp; `undefined < n` is false, so a
  // token with no exp would never expire.
  if (/payload\.exp\s*<\s*Date\.now\(\)/.test(content) && !/typeof payload\.exp !== 'number'/.test(content)) {
    flag('HIGH', f, 0, 'verifyJWT accepts a token with no exp', "Require typeof payload.exp === 'number' before the comparison.");
  }

  // Account delete must require current_password.
  // Match "function deleteAccount" and check the immediate body for current_password.
  const deleteAcctMatch = content.match(/async\s+function\s+deleteAccount\s*\([^)]*\)\s*\{([\s\S]{0,600})/);
  if (deleteAcctMatch && !/current_password/.test(deleteAcctMatch[1])) {
    flag('HIGH', f, 0, 'deleteAccount missing password re-prompt', 'Require current_password before deleting an account.');
  }

  // Reset / verify tokens must be hashed at rest.
  // We detect this by requiring `sha256Hex` to appear in any file that writes
  // to reset_tokens or email_verification_tokens.
  if (/INSERT\s+(?:OR\s+REPLACE\s+)?INTO\s+reset_tokens/i.test(content) && !/sha256Hex/.test(content)) {
    flag('HIGH', f, 0, 'reset_tokens stored raw', 'Hash with sha256Hex before storage.');
  }
  if (/INSERT\s+INTO\s+email_verification_tokens/i.test(content) && !/sha256Hex/.test(content)) {
    flag('HIGH', f, 0, 'email_verification_tokens stored raw', 'Hash with sha256Hex before storage.');
  }

  // CSP `'unsafe-inline'` on script-src — DEFERRED for graveyard. Tracked as
  // a MEDIUM here so it's visible without blocking deploys.
  const cspMatch = content.match(/script-src[^;'"]*['"]unsafe-inline['"][^;]*/i);
  if (cspMatch) {
    flag('MEDIUM', f, 0, 'CSP script unsafe-inline (deferred)', 'Manual extraction job. Track separately.');
  }
}

// ── HTML asset checks (public/) ────────────────────────────────────────────
const htmlFiles = listFiles(join(repoRoot, 'public'), ['.html']);

for (const f of htmlFiles) {
  const content = readFileSync(f, 'utf8');
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    const ln = idx + 1;

    // target=_blank without rel=noopener.
    const linkRe = /<a\b[^>]*\btarget\s*=\s*["']_blank["'][^>]*>/gi;
    const matches = line.match(linkRe);
    if (matches) {
      for (const tag of matches) {
        if (!/\brel\s*=\s*["'][^"']*\bnoopener\b/i.test(tag)) {
          flag('LOW', f, ln, 'target=_blank without rel=noopener', tag.slice(0, 80));
        }
      }
    }

    // CDN script without SRI hash.
    const cdnScript = line.match(/<script[^>]+src\s*=\s*["']https:\/\/(cdn\.|unpkg\.|cdnjs\.)[^"']+["'][^>]*>/gi);
    if (cdnScript) {
      for (const tag of cdnScript) {
        if (!/\bintegrity\s*=/i.test(tag)) {
          flag('MEDIUM', f, ln, 'CDN script without SRI', tag.slice(0, 80));
        }
      }
    }

    // Newsletter / marketing consent checkbox default-checked — GDPR violation.
    const checkboxMatches = line.match(/<input\b[^>]*\btype\s*=\s*["']checkbox["'][^>]*>/gi);
    if (checkboxMatches) {
      for (const tag of checkboxMatches) {
        if (/\b(newsletter|marketing|subscribe|opt[-_]?in|promo|emails?)\b/i.test(tag) && /\bchecked\b/i.test(tag)) {
          flag('HIGH', f, ln, 'consent checkbox default-checked', 'Pre-checked consent boxes violate GDPR/ePrivacy.');
        }
      }
    }

    // Password fields with minlength < 10.
    const pwInput = line.match(/<input\b[^>]*type=["']password["'][^>]*>/gi);
    if (pwInput) {
      for (const tag of pwInput) {
        const ml = tag.match(/\bminlength\s*=\s*["'](\d+)/);
        if (ml && parseInt(ml[1], 10) < 10) {
          flag('HIGH', f, ln, 'password minlength < 10', tag.slice(0, 80));
        }
      }
    }
  });
}

// ── Migration checks ────────────────────────────────────────────────────────
const migrationsDir = join(repoRoot, 'migrations');
if (existsSync(migrationsDir)) {
  const migrationFiles = readdirSync(migrationsDir).filter(f => f.endsWith('.sql'));
  const allMigrationContent = migrationFiles
    .map(f => readFileSync(join(migrationsDir, f), 'utf8'))
    .join('\n');
  const schemaContent = existsSync(join(repoRoot, 'schema.sql'))
    ? readFileSync(join(repoRoot, 'schema.sql'), 'utf8')
    : '';
  const combined = allMigrationContent + '\n' + schemaContent;

  // email_verification_tokens must be created somewhere.
  if (!/CREATE TABLE[^;]*email_verification_tokens/i.test(combined)) {
    flag('HIGH', migrationsDir, 0, 'email_verification_tokens table missing', 'Worker references it; must exist in schema or migration.');
  }
  // users.email_verified column must be created somewhere.
  if (!/email_verified/i.test(combined)) {
    flag('HIGH', migrationsDir, 0, 'users.email_verified missing', 'Worker writes to this column; must exist.');
  }
}

// ── Report ─────────────────────────────────────────────────────────────────
if (findings.length === 0) {
  console.log(`   scanned ${srcFiles.length} src + ${htmlFiles.length} html files, no security regressions found`);
  process.exit(0);
}

const high = findings.filter(f => f.severity === 'HIGH');
const med  = findings.filter(f => f.severity === 'MEDIUM');
const low  = findings.filter(f => f.severity === 'LOW');

console.error(`   security scan: ${high.length} HIGH, ${med.length} MEDIUM, ${low.length} LOW`);
for (const f of findings) {
  const where = f.line ? `${f.file}:${f.line}` : f.file;
  console.error(`     [${f.severity}] ${where}  '${f.rule}'  -- ${f.detail}`);
}

// Block on HIGH; warn-only on MEDIUM/LOW.
if (high.length > 0) process.exit(1);
console.error('   (warnings only -- deploy continues)');
process.exit(0);
