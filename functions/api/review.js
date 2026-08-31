const KV_PREFIX = "order:";
const MAX_KEYS = 1000;
const RULES_KEY = "rules";

function sanitizeString(value) {
  if (typeof value !== "string") return "";
  return value.replace(/[\x00-\x1f\x7f]/g, "").slice(0, 5000);
}

function securityHeaders(extra = {}) {
  return {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    ...extra,
  };
}

async function isAdminRequest(context) {
  const auth = context.request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) {
    const token = auth.slice(7).trim();
    if (token) {
      const expected = await context.env.ORDERS.get("admin_api_token", "text");
      if (expected === token) return true;
    }
  }

  const cookieHeader = context.request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/admin_token=([^;]+)/);
  if (match) {
    const token = decodeURIComponent(match[1]);
    const expected = await context.env.ORDERS.get("admin_api_token", "text");
    if (expected && expected === token) return true;
  }

  return false;
}

function isSameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (origin) {
    const url = new URL(request.url);
    return origin === `${url.protocol}//${url.host}`;
  }

  const host = request.headers.get("Host");
  if (!host) return false;
  const url = new URL(request.url);
  return host === url.host;
}

async function getRules(env) {
  try {
    const raw = await env.ORDERS.get(RULES_KEY, "text");
    if (!raw) return {};
    return JSON.parse(raw);
  } catch (e) {
    return {};
  }
}

function validateTier(order, rules) {
  const tier = order.tier || "";
  const size = parseFloat(order.file_size_kb) || 0;
  for (const t of rules.tiers || []) {
    if (tier === t.label || tier === t.id) {
      return { pass: size < t.max_size_kb, actual: size, limit: t.max_size_kb, tier: t.label || tier };
    }
  }
  const tierBase = String(tier).split("(")[0].trim().toLowerCase();
  for (const t of rules.tiers || []) {
    const id = String(t.id || "").toLowerCase();
    const base = String(t.label || "").split("(")[0].trim().toLowerCase();
    if (id && tierBase === id) {
      return { pass: size < t.max_size_kb, actual: size, limit: t.max_size_kb, tier: t.label || tier };
    }
    if (base && tierBase === base) {
      return { pass: size < t.max_size_kb, actual: size, limit: t.max_size_kb, tier: t.label || tier };
    }
  }
  return { pass: false, actual: size, limit: 0, tier: tier || "unknown" };
}

function validateRequiredFields(order, rules) {
  const missing = [];
  const all = [];
  if (rules.required_fields) {
    for (const group of Object.values(rules.required_fields)) {
      if (Array.isArray(group)) all.push(...group);
    }
  }
  for (const field of all) {
    if (!order[field] || !String(order[field]).trim()) {
      missing.push(field);
    }
  }
  return { pass: missing.length === 0, missing };
}

function validateUrls(order, rules) {
  const issues = [];
  const urls = [order.project_url, order.source_url].filter(Boolean);
  for (const url of urls) {
    if (!/^https?:\/\//i.test(url)) {
      issues.push("Non-HTTPS URL");
    }
  }
  const sourceRepo = parseGitHubRepo(order.source_url);
  const projectRepo = parseGitHubRepo(order.project_url);
  if (!sourceRepo && !projectRepo) {
    issues.push("Source URL doesn't match GitHub repo pattern");
  }
  return { pass: issues.length === 0, issues };
}

function parseGitHubRepo(url) {
  if (!url || typeof url !== "string") return null;
  let cleaned = url.trim().replace(/\/+$/, "");
  cleaned = cleaned.replace(/\/tree\/[^\/]*\/?$/i, "");
  cleaned = cleaned.replace(/\/blob\/[^\/]*\/?$/i, "");
  cleaned = cleaned.replace(/\/commit\/[^\/]*\/?$/i, "");
  const full = cleaned.match(/https?:\/\/github\.com\/([^\/]+)\/([^\/]+)/i);
  if (full) return { owner: full[1], repo: full[2].replace(/\.git$/i, "") };
  const short = cleaned.match(/^([^\/]+)\/([^\/]+)$/);
  if (short) return { owner: short[1], repo: short[2].replace(/\.git$/i, "") };
  return null;
}

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function detectObfuscation(code, rules) {
  const obf = rules.github_check?.obfuscation_rules || {};
  if (obf.enabled === false) return { obfuscated: false, reasons: [] };

  const reasons = [];
  const lower = code.toLowerCase();
  const suspiciousPatterns = obf.suspicious_patterns || [];

  for (const pattern of suspiciousPatterns) {
    if (pattern === "\\x") {
      const count = (lower.match(/\\x[0-9a-f]{2}/g) || []).length;
      if (count > 5) reasons.push(`High density of hex escapes (${count}).`);
    } else if (pattern === "\\u") {
      const count = (lower.match(/\\u[0-9a-f]{4}/g) || []).length;
      if (count > 5) reasons.push(`High density of unicode escapes (${count}).`);
    } else if (lower.includes(pattern.toLowerCase())) {
      reasons.push(`Suspicious pattern: ${pattern}`);
    }
  }

  const lines = code.split(/[\n\r]+/);
  let highEntropyChunks = 0;
  let totalChunks = 0;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) continue;
    const chunks = trimmed.match(/(?:["'`])([^"'`]{10,})(?:["'`])/g) || [];
    for (const chunk of chunks) {
      totalChunks++;
      const inner = chunk.slice(1, -1);
      const ent = shannonEntropy(inner);
      const threshold = obf.min_entropy_threshold || 4.5;
      if (ent > threshold && inner.length > 20) {
        highEntropyChunks++;
      }
    }
  }
  const ratio = obf.max_entropy_chunk_ratio || 0.6;
  if (totalChunks > 0 && highEntropyChunks / totalChunks > ratio) {
    reasons.push(`High-entropy strings detected (${highEntropyChunks}/${totalChunks} chunks above threshold).`);
  }

  const obfuscated = reasons.length > 0;
  return { obfuscated, reasons };
}

async function fetchGitHubTree(owner, repo, branch, token) {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "YouSpudReview/1.0" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const branches = [branch, "main", "master"];
  const tried = [];
  for (const br of branches) {
    if (!br || tried.includes(br)) continue;
    tried.push(br);
    const apiUrl = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(br)}?recursive=1`;
    const resp = await fetch(apiUrl, { headers });
    if (resp.ok) {
      const data = await resp.json();
      if (data.tree || Array.isArray(data.tree)) {
        return data.tree;
      }
      throw new Error("Invalid GitHub tree response.");
    }
    const text = await resp.text().catch(() => "");
    if (resp.status !== 404) {
      throw new Error(`GitHub API ${resp.status}: ${text.slice(0, 200)}`);
    }
  }
  throw new Error(`GitHub API 404: Branch not found. Tried: ${tried.join(", ")}`);
}

async function fetchGitHubContent(owner, repo, path, token) {
  const apiUrl = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodeURIComponent(path)}`;
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "YouSpudReview/1.0" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const resp = await fetch(apiUrl, { headers });
  if (!resp.ok) return null;
  const data = await resp.json();
  if (data.encoding === "base64" && data.content) {
    try {
      return decodeURIComponent(escape(atob(data.content.replace(/\n/g, ""))));
    } catch (e) {
      return null;
    }
  }
  return data.content || null;
}

function filterCodeFiles(tree, rules) {
  const include = new Set((rules.github_check?.include_extensions || []).map(e => e.toLowerCase()));
  const exclude = new Set((rules.github_check?.exclude_extensions || []).map(e => e.toLowerCase()));
  const results = [];
  let totalBytes = 0;
  for (const item of tree) {
    if (item.type !== "blob") continue;
    const path = (item.path || "").toLowerCase();
    const dot = path.lastIndexOf(".");
    if (dot === -1) continue;
    const ext = path.slice(dot);
    if (exclude.has(ext)) continue;
    if (include.size > 0 && !include.has(ext)) continue;
    const size = typeof item.size === "number" ? item.size : 0;
    totalBytes += size;
    results.push({ path: item.path, size });
  }
  return { files: results, totalBytes };
}

function checkForbiddenFilesAndDirs(tree, rules) {
  const issues = [];
  const forbiddenFiles = new Set((rules.github_check?.forbidden_files || []).map(f => f.toLowerCase()));
  const forbiddenDirs = new Set((rules.github_check?.forbidden_dirs || []).map(d => d.toLowerCase()));
  const forbiddenPatterns = rules.github_check?.forbidden_patterns || [];

  for (const item of tree) {
    const path = (item.path || "").toLowerCase();
    const parts = path.split("/");
    const fileName = parts[parts.length - 1];

    if (forbiddenFiles.has(fileName)) {
      issues.push(`Forbidden file: ${item.path}`);
    }
    for (const dir of parts) {
      if (forbiddenDirs.has(dir)) {
        issues.push(`Forbidden directory: ${item.path}`);
        break;
      }
    }
  }

  return { issues, forbiddenFiles, forbiddenDirs, forbiddenPatterns };
}

async function checkFileContents(owner, repo, files, rules, token) {
  const issues = [];
  const patterns = rules.github_check?.forbidden_patterns || [];
  if (!patterns.length) return issues;

  const checked = new Set();
  for (const file of files.slice(0, 20)) {
    if (file.size > 100 * 1024) continue;
    const ext = file.path.slice(file.path.lastIndexOf(".")).toLowerCase();
    if (![".js", ".html", ".css", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".json"].includes(ext)) continue;
    if (checked.has(file.path)) continue;
    checked.add(file.path);

    const content = await fetchGitHubContent(owner, repo, file.path, token);
    if (!content) continue;
    const lower = content.toLowerCase();
    for (const pattern of patterns) {
      if (lower.includes(pattern.toLowerCase())) {
        issues.push(`Forbidden pattern "${pattern}" found in ${file.path}`);
      }
    }
  }
  return issues;
}

async function checkGitHubRepo(order, rules) {
  const repo = parseGitHubRepo(order.source_url) || parseGitHubRepo(order.project_url);
  if (!repo) {
    return { checked: false, reason: "No GitHub repo URL found." };
  }
  const token = rules.github_check?.github_token || "";
  const branch = rules.github_check?.default_branch || "main";
  let tree;
  try {
    tree = await fetchGitHubTree(repo.owner, repo.repo, branch, token);
  } catch (err) {
    const msg = err.message || "Unknown error";
    if (msg.includes("403") || msg.includes("rate limit")) {
      return { checked: true, repo: `${repo.owner}/${repo.repo}`, branch, actual_kb: 0, declared_kb: parseFloat(order.file_size_kb) || 0, tier_limit_kb: getTierLimit(order.tier, rules), strict: rules.github_check?.strict_size_limit !== false, files_checked: 0, pass: true, issues: ["GitHub API rate limit exceeded. Review passed — verify manually."], rate_limited: true, sample_files: [] };
    }
    if (msg.includes("404")) {
      return { checked: true, repo: `${repo.owner}/${repo.repo}`, branch, actual_kb: 0, declared_kb: parseFloat(order.file_size_kb) || 0, tier_limit_kb: getTierLimit(order.tier, rules), strict: rules.github_check?.strict_size_limit !== false, files_checked: 0, pass: true, issues: [`GitHub branch not found: ${msg}. Review passed — verify manually.`], rate_limited: false, sample_files: [] };
    }
    return { checked: false, reason: "GitHub check failed: " + msg, pass: false, actual_kb: 0, declared_kb: parseFloat(order.file_size_kb) || 0, tier_limit_kb: getTierLimit(order.tier, rules), files_checked: 0, issues: [msg], sample_files: [] };
  }
  const { files, totalBytes } = filterCodeFiles(tree, rules);
  const actualKb = totalBytes / 1024;
  const declaredKb = parseFloat(order.file_size_kb) || 0;
  const tierLimit = getTierLimit(order.tier, rules);
  let pass = true;
  let issues = [];
  const strict = rules.github_check?.strict_size_limit !== false;
  if (strict && tierLimit > 0 && actualKb > tierLimit) {
    pass = false;
    issues.push(`Actual code (${actualKb.toFixed(1)} KB) exceeds tier limit (${tierLimit} KB).`);
  }
  if (declaredKb > 0 && actualKb > declaredKb) {
    issues.push(`Actual code (${actualKb.toFixed(1)} KB) is larger than declared (${declaredKb} KB).`);
  }
  if (files.length === 0) {
    pass = false;
    issues.push("No matching code files found in repo.");
  }

  const forbiddenCheck = checkForbiddenFilesAndDirs(tree, rules);
  issues.push(...forbiddenCheck.issues);
  if (forbiddenCheck.issues.length > 0) {
    pass = false;
  }

  const contentIssues = await checkFileContents(repo.owner, repo.repo, files, rules, token);
  issues.push(...contentIssues);
  if (contentIssues.length > 0) {
    pass = false;
  }

  const obfuscationIssues = await checkObfuscationInFiles(repo.owner, repo.repo, files, rules, token);
  issues.push(...obfuscationIssues);
  if (obfuscationIssues.length > 0) {
    pass = false;
  }

  return {
    checked: true,
    repo: `${repo.owner}/${repo.repo}`,
    branch,
    actual_kb: actualKb,
    declared_kb: declaredKb,
    tier_limit_kb: tierLimit,
    strict,
    files_checked: files.length,
    pass,
    issues,
    sample_files: files.slice(0, 10),
  };
}

async function checkObfuscationInFiles(owner, repo, files, rules, token) {
  const issues = [];
  const obf = rules.github_check?.obfuscation_rules || {};
  if (obf.enabled === false) return issues;

  const checked = new Set();
  for (const file of files.slice(0, 15)) {
    if (file.size > 200 * 1024) continue;
    const ext = file.path.slice(file.path.lastIndexOf(".")).toLowerCase();
    if (![".js", ".html", ".css", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"].includes(ext)) continue;
    if (checked.has(file.path)) continue;
    checked.add(file.path);

    const content = await fetchGitHubContent(owner, repo, file.path, token);
    if (!content) continue;

    const result = detectObfuscation(content, rules);
    if (result.obfuscated && result.reasons.length > 0) {
      issues.push(...result.reasons.map(r => `${r} (in ${file.path})`));
    }
  }
  return issues;
}

function getTierLimit(tier, rules) {
  if (!tier || !Array.isArray(rules.tiers)) return 0;
  for (const t of rules.tiers) {
    if (tier === t.label || tier === t.id) {
      return typeof t.max_size_kb === "number" ? t.max_size_kb : 0;
    }
  }
  const tierBase = String(tier).split("(")[0].trim().toLowerCase();
  for (const t of rules.tiers) {
    const id = String(t.id || "").toLowerCase();
    const base = String(t.label || "").split("(")[0].trim().toLowerCase();
    if (id && tierBase === id) {
      return typeof t.max_size_kb === "number" ? t.max_size_kb : 0;
    }
    if (base && tierBase === base) {
      return typeof t.max_size_kb === "number" ? t.max_size_kb : 0;
    }
  }
  return 0;
}

export async function onRequestGet(context) {
  if (!(await isAdminRequest(context))) {
    return new Response(JSON.stringify({ error: "Unauthorized." }), {
      status: 401,
      headers: securityHeaders(),
    });
  }

  if (!isSameOrigin(context.request)) {
    return new Response(JSON.stringify({ error: "Invalid origin." }), {
      status: 403,
      headers: securityHeaders(),
    });
  }

  const url = new URL(context.request.url);
  const orderId = url.searchParams.get("id");

  if (!orderId) {
    return new Response(JSON.stringify({ error: "Missing order id." }), {
      status: 400,
      headers: securityHeaders(),
    });
  }

  const list = await context.env.ORDERS.list({ limit: MAX_KEYS, prefix: KV_PREFIX });
  let order = null;
  for (const key of list.keys) {
    const raw = await context.env.ORDERS.get(key.name, "json");
    if (raw && raw._id === orderId) {
      order = raw;
      break;
    }
  }

  if (!order) {
    return new Response(JSON.stringify({ error: "Order not found." }), {
      status: 404,
      headers: securityHeaders(),
    });
  }

  const rules = await getRules(context.env);
  const tierCheck = validateTier(order, rules);
  const fieldsCheck = validateRequiredFields(order, rules);
  const urlCheck = validateUrls(order, rules);
  const githubCheck = rules.github_check?.enabled !== false
    ? await checkGitHubRepo(order, rules)
    : { checked: false, reason: "GitHub check disabled." };

  const orderForReview = {
    _id: order._id,
    project_name: order.project_name,
    project_url: order.project_url,
    source_url: order.source_url,
    file_size_kb: order.file_size_kb,
    description: order.description,
    tier: order.tier,
    hc_name: order.hc_name,
    hc_email: order.hc_email,
    hc_verified: order.hc_verified,
    deadline: order.deadline,
    accepted: order.accepted,
  };

  const reviewPassed = tierCheck.pass && fieldsCheck.pass && urlCheck.pass && (githubCheck.pass !== false);

  return new Response(JSON.stringify({
    ok: true,
    order_id: orderId,
    review: {
      passed: reviewPassed,
      tier: tierCheck,
      fields: fieldsCheck,
      urls: urlCheck,
      github: githubCheck,
    },
    order: orderForReview,
  }), {
    status: 200,
    headers: securityHeaders(),
  });
}
