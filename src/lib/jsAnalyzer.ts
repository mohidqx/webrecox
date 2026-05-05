import { parse } from 'acorn';
import { simple as walkSimple } from 'acorn-walk';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Category = 'endpoint' | 'secret' | 'bug' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

export interface JSAnalysisFinding {
  category: Category;
  severity: Severity;
  type: string;
  value: string;
  context?: string;
  file?: string;
  line?: number;
  confidence: Confidence;
  verified?: boolean;
  source?: 'ast' | 'regex' | 'heuristic';
}

export interface JSAnalysisResult {
  file: string;
  endpoints: JSAnalysisFinding[];
  secrets: JSAnalysisFinding[];
  bugs: JSAnalysisFinding[];
  info: JSAnalysisFinding[];
  parseError?: string;
  totalLOC: number;
}

const AXIOS_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request']);
const ENDPOINT_EXT_RE = /\.(?:css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp[34]|wav|pdf|zip|gz|tar)(\?|$)/i;
const ENDPOINT_FALSE_POSITIVES = [/^[a-z]+$/i, /^\d+$/, /^[#@%&]/, /^use\s/i, /^\s*$/];
const CACHE_TTL_MS = 1000 * 60 * 60 * 6;
const SCRIPT_CACHE_KEY = 'webrecox.jsCrawler.v2';
const BODY_CACHE_KEY = 'webrecox.jsBodies.v2';

const SECRET_PATTERNS: { name: string; sev: Severity; re: RegExp }[] = [
  { name: 'AWS Access Key', sev: 'CRITICAL', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'AWS Secret Key (40 char b64)', sev: 'CRITICAL', re: /(?:aws_secret|aws_secret_access_key|secret_key)\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']/gi },
  { name: 'Google API Key', sev: 'HIGH', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: 'Slack Token', sev: 'CRITICAL', re: /\bxox[abprs]-[A-Za-z0-9-]{10,48}\b/g },
  { name: 'GitHub Token', sev: 'CRITICAL', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g },
  { name: 'Stripe Live Key', sev: 'CRITICAL', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g },
  { name: 'Stripe Test Key', sev: 'MEDIUM', re: /\b(?:sk|rk|pk)_test_[0-9a-zA-Z]{20,}\b/g },
  { name: 'Generic Bearer Token', sev: 'HIGH', re: /Bearer\s+[A-Za-z0-9\-_=.+/]{30,}/g },
  { name: 'JWT', sev: 'MEDIUM', re: /\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/g },
  { name: 'API Key (generic)', sev: 'HIGH', re: /(?:api[_-]?key|apikey|api_secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']/gi },
  { name: 'Firebase URL', sev: 'MEDIUM', re: /https?:\/\/[a-z0-9-]+\.firebaseio\.com/gi },
  { name: 'Mailgun API Key', sev: 'HIGH', re: /\bkey-[0-9a-zA-Z]{32}\b/g },
  { name: 'Twilio SID', sev: 'HIGH', re: /\bAC[a-z0-9]{32}\b/g },
  { name: 'Private Key', sev: 'CRITICAL', re: /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----/g },
];

const BUG_PATTERNS: { name: string; sev: Severity; re: RegExp; desc: string }[] = [
  { name: 'eval()', sev: 'CRITICAL', re: /\beval\s*\(\s*[^"')]/g, desc: 'Dynamic eval enables arbitrary code execution.' },
  { name: 'new Function()', sev: 'CRITICAL', re: /\bnew\s+Function\s*\(/g, desc: 'Function constructor is equivalent to eval.' },
  { name: 'innerHTML sink', sev: 'HIGH', re: /\.innerHTML\s*=\s*[^"`'<]/g, desc: 'Dynamic innerHTML can lead to DOM XSS.' },
  { name: 'document.write', sev: 'HIGH', re: /document\.write(?:ln)?\s*\(/g, desc: 'document.write is a known XSS sink.' },
  { name: 'dangerouslySetInnerHTML', sev: 'HIGH', re: /dangerouslySetInnerHTML/g, desc: 'React XSS escape hatch.' },
  { name: 'postMessage(*)', sev: 'HIGH', re: /\.postMessage\s*\([^,)]+,\s*["']\*["']\s*\)/g, desc: 'Wildcard origin enables cross-frame leaks.' },
  { name: 'localStorage credential', sev: 'HIGH', re: /(?:local|session)Storage\.\s*(?:setItem|getItem)\s*\(\s*["'`](?:token|password|secret|api[_-]?key|jwt|auth|credential)/gi, desc: 'Sensitive data in web storage.' },
  { name: 'Disabled SSL verify', sev: 'HIGH', re: /(?:rejectUnauthorized|verifySsl|sslVerify|insecure)\s*[:=]\s*false/gi, desc: 'SSL/TLS verification disabled.' },
  { name: 'CORS wildcard', sev: 'MEDIUM', re: /access-control-allow-origin\s*[:=]\s*["']\*["']/gi, desc: 'CORS wildcard in code.' },
  { name: 'Hardcoded password', sev: 'HIGH', re: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']/gi, desc: 'Plaintext password literal.' },
  { name: 'Console logs sensitive', sev: 'LOW', re: /console\.(?:log|error|warn|info)\s*\([^)]*(?:password|token|secret|jwt|apikey)/gi, desc: 'Sensitive value logged.' },
  { name: 'Debug enabled', sev: 'LOW', re: /\b(?:debug|DEBUG)\s*[:=]\s*(?:true|1)\b/g, desc: 'Debug flag in client code.' },
  { name: 'TODO/FIXME', sev: 'INFO', re: /\/\/\s*(?:TODO|FIXME|HACK|XXX):\s*[^\n]{4,120}/g, desc: 'Developer note in production code.' },
  { name: 'Source map exposed', sev: 'LOW', re: /\/\/[#@]\s*sourceMappingURL\s*=\s*[^\s]+/g, desc: 'Source map reference reveals original code.' },
];

const REGEX_ENDPOINT_PATTERNS: RegExp[] = [
  /["'`](\/(?:api|v\d+|graphql|rest|gateway|service|admin|user|auth|account|oauth|public|internal|private|backend)\/[A-Za-z0-9_\-./{}%?=&]+)["'`]/g,
  /["'`](https?:\/\/[A-Za-z0-9.\-]+\/[A-Za-z0-9_\-./{}%?=&]*)["'`]/g,
  /(?:url|endpoint|path|uri|baseURL|baseUrl|apiUrl|apiBase)\s*[:=]\s*["'`]([^"'`]{2,200})["'`]/gi,
  /["'`](\/[a-z0-9_\-./]{3,})["'`]\s*\+/gi,
];

function now() {
  return Date.now();
}

function readCache<T>(key: string): Record<string, { ts: number; data: T }> {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return {};
    return JSON.parse(raw) as Record<string, { ts: number; data: T }>;
  } catch {
    return {};
  }
}

function writeCache<T>(key: string, value: Record<string, { ts: number; data: T }>) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // ignore quota issues
  }
}

function getCached<T>(key: string, id: string): T | null {
  const db = readCache<T>(key);
  const item = db[id];
  if (!item) return null;
  if (now() - item.ts > CACHE_TTL_MS) {
    delete db[id];
    writeCache(key, db);
    return null;
  }
  return item.data;
}

function setCached<T>(key: string, id: string, data: T) {
  const db = readCache<T>(key);
  db[id] = { ts: now(), data };
  writeCache(key, db);
}

function mergeSignals(signals: (AbortSignal | undefined)[]): AbortSignal | undefined {
  const filtered = signals.filter(Boolean) as AbortSignal[];
  if (!filtered.length) return undefined;
  const controller = new AbortController();
  const abort = () => controller.abort();
  filtered.forEach(signal => {
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
  });
  return controller.signal;
}

function lineOf(text: string, idx: number): number {
  let line = 1;
  for (let i = 0; i < idx && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

function dedupe(arr: JSAnalysisFinding[]): JSAnalysisFinding[] {
  const seen = new Set<string>();
  const out: JSAnalysisFinding[] = [];
  for (const f of arr) {
    const k = `${f.category}|${f.type}|${f.value}|${f.file}|${f.line}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out;
}

function isLikelyEndpoint(s: string): { ok: boolean; confidence: Confidence } {
  if (!s || s.length < 2 || s.length > 500) return { ok: false, confidence: 'low' };
  if (ENDPOINT_EXT_RE.test(s)) return { ok: false, confidence: 'low' };
  if (ENDPOINT_FALSE_POSITIVES.some(re => re.test(s))) return { ok: false, confidence: 'low' };
  if (/^https?:\/\/[a-z0-9.\-]+\/[a-z0-9_\-./?=&{}%]+/i.test(s)) return { ok: true, confidence: 'high' };
  if (/^\/(api|v\d|graphql|rest|gateway|service|admin|user|auth|login|account)\b/i.test(s)) return { ok: true, confidence: 'high' };
  if (/^\/[a-z0-9_\-./{}%]+$/i.test(s) && s.includes('/') && s.length >= 4) {
    if (/[MLHVCSQTAZ\d.,\s\-]{20,}/.test(s) && /[MLHVCSQTAZ]/.test(s)) return { ok: false, confidence: 'low' };
    return { ok: true, confidence: 'medium' };
  }
  return { ok: false, confidence: 'low' };
}

function calleeName(node: any): string {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const obj = calleeName(node.object);
    const prop = node.property?.name || node.property?.value || '';
    return obj ? `${obj}.${prop}` : String(prop || '');
  }
  return '';
}

function buildResolver(ast: any, code: string) {
  const vars = new Map<string, string>();

  const resolveNode = (node: any, depth = 0): string | null => {
    if (!node || depth > 4) return null;
    if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
    if (node.type === 'TemplateLiteral') {
      const parts: string[] = [];
      for (let i = 0; i < node.quasis.length; i++) {
        parts.push(node.quasis[i]?.value?.cooked || '');
        if (node.expressions[i]) {
          const expr = resolveNode(node.expressions[i], depth + 1);
          parts.push(expr ?? '${…}');
        }
      }
      return parts.join('');
    }
    if (node.type === 'BinaryExpression' && node.operator === '+') {
      const left = resolveNode(node.left, depth + 1);
      const right = resolveNode(node.right, depth + 1);
      if (left === null && right === null) return null;
      return `${left ?? ''}${right ?? ''}`;
    }
    if (node.type === 'Identifier') return vars.get(node.name) ?? null;
    if (node.type === 'ConditionalExpression') return resolveNode(node.consequent, depth + 1) ?? resolveNode(node.alternate, depth + 1);
    if (node.type === 'MemberExpression' && node.object?.type === 'Identifier' && node.property?.type === 'Identifier') {
      return vars.get(`${node.object.name}.${node.property.name}`) ?? null;
    }
    if (node.type === 'ObjectExpression') {
      const urlProp = node.properties?.find((p: any) => ['url', 'baseURL', 'baseUrl', 'uri', 'endpoint', 'path'].includes(p.key?.name || p.key?.value));
      return urlProp ? resolveNode(urlProp.value, depth + 1) : null;
    }
    return null;
  };

  walkSimple(ast, {
    VariableDeclarator(node: any) {
      if (node.id?.type !== 'Identifier') return;
      const value = resolveNode(node.init, 0);
      if (typeof value === 'string' && value.length < 400) vars.set(node.id.name, value);
    },
    AssignmentExpression(node: any) {
      if (node.left?.type === 'Identifier') {
        const value = resolveNode(node.right, 0);
        if (typeof value === 'string' && value.length < 400) vars.set(node.left.name, value);
      }
      if (node.left?.type === 'MemberExpression' && node.left.object?.type === 'Identifier' && node.left.property?.type === 'Identifier') {
        const value = resolveNode(node.right, 0);
        if (typeof value === 'string' && value.length < 400) vars.set(`${node.left.object.name}.${node.left.property.name}`, value);
      }
    },
  });

  return { resolveNode, vars, code };
}

function extractEndpointsAST(code: string, file: string): JSAnalysisFinding[] {
  const out: JSAnalysisFinding[] = [];
  let ast: any;
  try {
    ast = parse(code, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      allowImportExportEverywhere: true,
      locations: false,
    });
  } catch {
    ast = parse(code, { ecmaVersion: 'latest', sourceType: 'script', allowReturnOutsideFunction: true });
  }

  const { resolveNode } = buildResolver(ast, code);

  const pushEndpoint = (value: string | null, node: any, type: string, confidence?: Confidence, verified = true) => {
    if (!value) return;
    const det = isLikelyEndpoint(value);
    if (!det.ok && !/^https?:\/\//i.test(value)) return;
    out.push({
      category: 'endpoint',
      severity: verified ? 'LOW' : det.confidence === 'high' ? 'LOW' : 'INFO',
      type,
      value,
      file,
      line: lineOf(code, node.start || 0),
      confidence: confidence || det.confidence,
      verified,
      source: 'ast',
      context: verified ? 'Verified network call path from AST' : 'AST-resolved candidate endpoint',
    });
  };

  walkSimple(ast, {
    CallExpression(node: any) {
      const name = calleeName(node.callee);
      const isFetch = name === 'fetch';
      const isAxiosCall = /^axios(\.[a-z]+)?$/i.test(name) || (node.callee?.object?.name === 'axios' && AXIOS_METHODS.has(node.callee?.property?.name));
      const isXhrOpen = node.callee?.type === 'MemberExpression' && node.callee.property?.name === 'open';
      const isJqAjax = /^\$\.(ajax|get|post|getJSON)$/.test(name);
      const isRequestCtor = name === 'Request';

      if (isFetch || isJqAjax || isRequestCtor) {
        pushEndpoint(resolveNode(node.arguments?.[0]), node, `${name}() call`, 'high', true);
      } else if (isAxiosCall) {
        if (node.arguments?.[0]?.type === 'ObjectExpression') {
          pushEndpoint(resolveNode(node.arguments[0]), node, 'axios config call', 'high', true);
        } else {
          pushEndpoint(resolveNode(node.arguments?.[0]), node, `${name}() call`, 'high', true);
        }
      } else if (isXhrOpen) {
        pushEndpoint(resolveNode(node.arguments?.[1]), node, 'XMLHttpRequest.open', 'high', true);
      }
    },
    NewExpression(node: any) {
      if (calleeName(node.callee) === 'WebSocket') {
        const value = resolveNode(node.arguments?.[0]);
        if (value && /^wss?:\/\//i.test(value)) {
          out.push({
            category: 'endpoint',
            severity: 'LOW',
            type: 'WebSocket endpoint',
            value,
            file,
            line: lineOf(code, node.start || 0),
            confidence: 'high',
            verified: true,
            source: 'ast',
            context: 'Verified WebSocket endpoint from AST',
          });
        }
      }
    },
    Literal(node: any) {
      if (typeof node.value !== 'string') return;
      const det = isLikelyEndpoint(node.value);
      if (!det.ok || det.confidence === 'low') return;
      out.push({
        category: 'endpoint',
        severity: det.confidence === 'high' ? 'LOW' : 'INFO',
        type: 'String literal endpoint',
        value: node.value,
        file,
        line: lineOf(code, node.start || 0),
        confidence: det.confidence,
        verified: false,
        source: 'heuristic',
        context: 'Literal matched endpoint heuristics',
      });
    },
  });

  return dedupe(out);
}

export function extractEndpointsRegex(code: string, file = 'inline.js'): JSAnalysisFinding[] {
  const out: JSAnalysisFinding[] = [];
  for (const pattern of REGEX_ENDPOINT_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const value = (m[1] || m[0]).slice(0, 400);
      const det = isLikelyEndpoint(value);
      if (!det.ok) continue;
      out.push({
        category: 'endpoint',
        severity: det.confidence === 'high' ? 'LOW' : 'INFO',
        type: 'Regex-extracted endpoint',
        value,
        file,
        line: lineOf(code, m.index),
        confidence: det.confidence,
        verified: false,
        source: 'regex',
        context: 'Recovered from minified/dynamic URL regex fallback',
      });
      if (out.length > 5000) break;
    }
  }
  return dedupe(out);
}

export function extractAllEndpoints(code: string, file = 'inline.js'): JSAnalysisFinding[] {
  const fromAst = (() => {
    try {
      return extractEndpointsAST(code, file);
    } catch {
      return [] as JSAnalysisFinding[];
    }
  })();
  return dedupe([...fromAst, ...extractEndpointsRegex(code, file)]);
}

export function analyzeJS(code: string, file = 'inline.js'): JSAnalysisResult {
  const endpoints: JSAnalysisFinding[] = [];
  const secrets: JSAnalysisFinding[] = [];
  const bugs: JSAnalysisFinding[] = [];
  const info: JSAnalysisFinding[] = [];
  let parseError: string | undefined;

  try {
    endpoints.push(...extractEndpointsAST(code, file));
  } catch (e: any) {
    parseError = e?.message || 'AST parse failed';
  }
  endpoints.push(...extractEndpointsRegex(code, file));

  for (const pat of SECRET_PATTERNS) {
    const re = new RegExp(pat.re.source, pat.re.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const value = (m[1] || m[0]).slice(0, 200);
      secrets.push({
        category: 'secret',
        severity: pat.sev,
        type: pat.name,
        value,
        file,
        line: lineOf(code, m.index),
        confidence: 'high',
        verified: true,
        source: 'regex',
      });
      if (secrets.length > 5000) break;
    }
  }

  for (const pat of BUG_PATTERNS) {
    const re = new RegExp(pat.re.source, pat.re.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const value = m[0].slice(0, 200);
      const category: Category = pat.sev === 'INFO' ? 'info' : 'bug';
      const target = category === 'info' ? info : bugs;
      target.push({
        category,
        severity: pat.sev,
        type: pat.name,
        value,
        context: pat.desc,
        file,
        line: lineOf(code, m.index),
        confidence: 'high',
        verified: true,
        source: 'regex',
      });
      if (bugs.length + info.length > 5000) break;
    }
  }

  return {
    file,
    endpoints: dedupe(endpoints).sort((a, b) => (a.verified === b.verified ? 0 : a.verified ? -1 : 1)),
    secrets: dedupe(secrets),
    bugs: dedupe(bugs),
    info: dedupe(info),
    parseError,
    totalLOC: code.split('\n').length,
  };
}

export const SEV_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export function groupBySeverity(findings: JSAnalysisFinding[]): Record<Severity, JSAnalysisFinding[]> {
  return findings.reduce<Record<Severity, JSAnalysisFinding[]>>((acc, finding) => {
    acc[finding.severity].push(finding);
    return acc;
  }, { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] });
}

export function aggregateAnalyses(results: JSAnalysisResult[]) {
  const endpoints = dedupe(results.flatMap(r => r.endpoints));
  const secrets = dedupe(results.flatMap(r => r.secrets));
  const bugs = dedupe(results.flatMap(r => r.bugs));
  const info = dedupe(results.flatMap(r => r.info));
  const everything = [...secrets, ...bugs, ...endpoints, ...info];
  return {
    totalFiles: results.length,
    totalLOC: results.reduce((sum, r) => sum + r.totalLOC, 0),
    endpoints,
    secrets,
    bugs,
    info,
    bySeverity: groupBySeverity(everything),
  };
}

function throwIfAborted(signal?: AbortSignal) {
  if (signal?.aborted) throw new DOMException('Operation cancelled', 'AbortError');
}

async function fetchJsBody(url: string, opts?: { timeoutMs?: number; signal?: AbortSignal; cacheKey?: string; useCache?: boolean }): Promise<string | null> {
  const timeoutMs = opts?.timeoutMs ?? 12000;
  const cacheId = `${opts?.cacheKey || 'global'}::${url}`;
  if (opts?.useCache !== false) {
    const cached = getCached<string>(BODY_CACHE_KEY, cacheId);
    if (cached) return cached;
  }

  const proxies = [
    (u: string) => u,
    (u: string) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
    (u: string) => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
    (u: string) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
  ];

  for (const proxy of proxies) {
    throwIfAborted(opts?.signal);
    try {
      const signal = mergeSignals([opts?.signal, AbortSignal.timeout(timeoutMs)]);
      const response = await fetch(proxy(url), { signal });
      if (!response.ok) continue;
      const text = await response.text();
      if (!text) continue;
      setCached(BODY_CACHE_KEY, cacheId, text);
      return text;
    } catch (error: any) {
      if (error?.name === 'AbortError') throw error;
    }
  }
  return null;
}

export async function discoverScriptUrls(targetUrl: string, opts?: { signal?: AbortSignal; useCache?: boolean }): Promise<string[]> {
  if (opts?.useCache !== false) {
    const cached = getCached<string[]>(SCRIPT_CACHE_KEY, targetUrl);
    if (cached) return cached;
  }
  const html = await fetchJsBody(targetUrl, { timeoutMs: 15000, signal: opts?.signal, cacheKey: targetUrl, useCache: opts?.useCache });
  if (!html) return [];
  const out = new Set<string>();
  let base: URL;
  try {
    base = new URL(targetUrl);
  } catch {
    return [];
  }

  let m: RegExpExecArray | null;
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  while ((m = re.exec(html)) !== null) {
    throwIfAborted(opts?.signal);
    try {
      const abs = new URL(m[1], base).toString();
      if (/\.js(\?|#|$)/.test(abs) || abs.endsWith('.js')) out.add(abs);
    } catch {
      // ignore
    }
  }
  const preload = /<link[^>]+rel=["'](?:preload|modulepreload)["'][^>]+href\s*=\s*["']([^"']+\.js[^"']*)["']/gi;
  while ((m = preload.exec(html)) !== null) {
    throwIfAborted(opts?.signal);
    try {
      out.add(new URL(m[1], base).toString());
    } catch {
      // ignore
    }
  }

  const urls = [...out].slice(0, 200);
  setCached(SCRIPT_CACHE_KEY, targetUrl, urls);
  return urls;
}

export async function crawlAndAnalyze(
  targetUrl: string,
  opts?: { maxFiles?: number; signal?: AbortSignal; onProgress?: (current: number, total: number, label: string) => void; useCache?: boolean },
): Promise<JSAnalysisResult[]> {
  const max = opts?.maxFiles ?? 100;
  const urls = (await discoverScriptUrls(targetUrl, { signal: opts?.signal, useCache: opts?.useCache })).slice(0, max);
  const out: JSAnalysisResult[] = [];
  const cacheKey = new URL(targetUrl).origin;

  opts?.onProgress?.(0, urls.length, `Discovered ${urls.length} script files`);
  for (let i = 0; i < urls.length; i++) {
    throwIfAborted(opts?.signal);
    const url = urls[i];
    opts?.onProgress?.(i, urls.length, `Analyzing ${i + 1}/${urls.length}: ${new URL(url).pathname.split('/').pop() || 'script.js'}`);
    const body = await fetchJsBody(url, { signal: opts?.signal, cacheKey, useCache: opts?.useCache });
    if (!body) {
      out.push({ file: url, endpoints: [], secrets: [], bugs: [], info: [], totalLOC: 0, parseError: 'fetch failed' });
      continue;
    }
    out.push(analyzeJS(body, url));
  }
  opts?.onProgress?.(urls.length, urls.length, `Completed analysis of ${urls.length} script files`);
  return out;
}
