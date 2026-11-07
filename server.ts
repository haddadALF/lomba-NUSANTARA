/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Full-Stack Real Detection Engine & Server
 * Zero Dummy Data • Real Evidence Only • Targeted at DVWA (192.168.100.75:8081)
 */

import express, { Request, Response, NextFunction } from 'express';
import { createServer } from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import { storage, StorageEngine } from './src/db/storage.js';
import { SecurityEvent, SecurityAlert, Incident, BlockedIpRecord } from './src/types/cybersecurity.js';
import { evaluateRequestPayload } from './src/engine/detectionEngine.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer(app);
const PORT = process.env.PORT || 3000;

// Serve public static assets directly (including /assets/security/403-forbidden.jpg)
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));

// Security Headers Middleware (Prioritas 1: Hardened HTTP headers)
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Request ID Tracing Middleware (Prioritas 2: End-to-end request tracing)
app.use((req: Request, res: Response, next: NextFunction) => {
  const reqId = (req.headers['x-request-id'] as string) || `REQ-${Date.now().toString().slice(-6)}-${crypto.randomBytes(3).toString('hex')}`;
  (req as any).id = reqId;
  res.setHeader('X-Request-Id', reqId);
  next();
});

// Size-limited payload parsers (<5MB)
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// In-Memory Sliding Window Rate Limiter (Prioritas 1)
interface RateLimitBucket {
  count: number;
  resetTime: number;
}
const rateLimitStore = new Map<string, RateLimitBucket>();

function rateLimiter(maxRequests: number, windowSeconds: number = 60) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (process.env.RATE_LIMIT_ENABLED === 'false') {
      return next();
    }
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || req.ip || '127.0.0.1';
    const routeKey = req.baseUrl || req.path.split('/')[2] || 'api';
    const key = `${routeKey}:${clientIp}`;
    const now = Date.now();
    const windowMs = windowSeconds * 1000;

    let bucket = rateLimitStore.get(key);
    if (!bucket || now > bucket.resetTime) {
      bucket = { count: 1, resetTime: now + windowMs };
      rateLimitStore.set(key, bucket);
    } else {
      bucket.count += 1;
    }

    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - bucket.count));
    res.setHeader('X-RateLimit-Reset', Math.ceil(bucket.resetTime / 1000));

    if (bucket.count > maxRequests) {
      const retryAfter = Math.ceil((bucket.resetTime - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({
        error: 'Too Many Requests',
        message: `Rate limit of ${maxRequests} requests per ${windowSeconds}s exceeded.`,
        retryAfterSeconds: retryAfter,
        requestId: (req as any).id,
      });
    }
    next();
  };
}

// Global API Rate Limiter (300 req/min)
app.use('/api', rateLimiter(300, 60));

// Stricter Rate Limiter for Ingestion Endpoints (120 req/min)
app.use('/api/ingest', rateLimiter(120, 60));

// Initialize Google GenAI Server-side Client
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

// SSE Subscribers for Real-Time Event & Alert Streaming
const sseClients: Set<Response> = new Set();

function broadcastSse(eventType: string, payload: any) {
  const data = JSON.stringify(payload);
  for (const client of sseClients) {
    try {
      client.write(`event: ${eventType}\ndata: ${data}\n\n`);
    } catch {
      sseClients.delete(client);
    }
  }
}

// Periodic SSE Keepalive Ping every 15s (Prioritas 4: Connection stability)
const sseKeepAliveInterval = setInterval(() => {
  for (const client of sseClients) {
    try {
      client.write(':keepalive\n\n');
    } catch {
      sseClients.delete(client);
    }
  }
}, 15000);

// Check initial health of DVWA target on startup asynchronously
storage.probeDvwaTarget().then((res) => {
  console.log(`[NUSANTARA-SMS] Initial DVWA Probe (192.168.100.75:8081): Reachable=${res.reachable} (${res.latencyMs || res.error})`);
});

// -------------------------------------------------------------
// REST API Endpoints
// -------------------------------------------------------------

// System Health & Monitoring Transparency (Prioritas 4: Component-by-Component Status)
app.get('/api/health', (req: Request, res: Response) => {
  const sensors = storage.getSensors();
  const collectorStatus = storage.getCollectorStatus();
  const dvwaSensor = sensors.find((s) => s.id === 'sensor-dvwa');
  const suricataSensor = sensors.find((s) => s.id === 'sensor-suricata');
  const wafSensor = sensors.find((s) => s.id === 'sensor-waf');
  const dbSensor = sensors.find((s) => s.id === 'sensor-database');

  const isDegraded = sensors.some((s) => s.connectionStatus === 'degraded' || s.connectionStatus === 'disconnected' || s.connectionStatus === 'waiting_telemetry');

  res.json({
    status: isDegraded ? 'degraded' : 'healthy',
    overallMonitoringState: isDegraded ? 'degraded' : 'optimal',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: '1.0.0-REAL-DEFENSE',
    targetAsset: 'http://192.168.100.75:8081',
    activeSensors: sensors.filter((s) => s.connectionStatus === 'connected').length,
    totalSensors: sensors.length,
    eventCount: storage.getEvents().length,
    alertCount: storage.getAlerts().length,
    incidentCount: storage.getIncidents().length,
    components: {
      suricataFeed: {
        status: suricataSensor?.connectionStatus || 'waiting_telemetry',
        feedActive: collectorStatus.suricataFeedActive,
        lastCollection: suricataSensor?.lastSuccessfulCollection || null,
        ingestedEvents: suricataSensor?.eventIngestionCount || 0,
      },
      wafInspection: {
        status: wafSensor?.connectionStatus || 'waiting_telemetry',
        feedActive: collectorStatus.wafFeedActive,
        lastCollection: wafSensor?.lastSuccessfulCollection || null,
      },
      dvwaTarget: {
        status: dvwaSensor?.connectionStatus || 'disconnected',
        targetUrl: 'http://192.168.100.75:8081',
        lastChecked: dvwaSensor?.lastSuccessfulCollection || null,
        errorDetail: dvwaSensor?.errorStatus || null,
      },
      databaseStorage: {
        status: 'connected',
        type: 'Atomic File Persistence (Crash-Resilient JSON Store)',
        persistenceEngine: 'Atomic File Persistence (Crash-Resilient JSON Store)',
        fileTarget: 'data/nusantara_db.json',
      },
      sseEventBus: {
        status: 'connected',
        clientSubscribers: sseClients.size,
        keepAlivePingSec: 15,
      },
    },
  });
});

// Real-Time SSE Stream Endpoint
app.get('/api/events/stream', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  sseClients.add(res);

  res.write(
    `event: init\ndata: ${JSON.stringify({
      message: 'Connected to Nusantara-SMS Live Event Bus',
      clientCount: sseClients.size,
      activeAlerts: storage.getAlerts().length,
    })}\n\n`
  );

  req.on('close', () => {
    sseClients.delete(res);
  });
});

// -------------------------------------------------------------
// 403 FORBIDDEN PAGE & AUTOMATIC ENFORCEMENT (Section 6)
// -------------------------------------------------------------
function renderForbidden403Html(params: {
  requestId: string;
  timestamp: string;
  category: string;
  reason: string;
  clientIp?: string;
}): string {
  const safeReqId = params.requestId.replace(/[<>&"]/g, '');
  const safeTime = params.timestamp.replace(/[<>&"]/g, '');
  const safeCategory = params.category.replace(/[<>&"]/g, '');
  const safeReason = params.reason.replace(/[<>&"]/g, '');

  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>403 Forbidden — NUSANTARA-SMS Security Protection</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #060A12;
      color: #E2E8F0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      max-width: 720px;
      width: 100%;
      background: #0B111E;
      border: 1px solid #1E2D4A;
      border-radius: 1.25rem;
      overflow: hidden;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.85);
    }
    .hero-img {
      width: 100%;
      height: auto;
      display: block;
      border-bottom: 1px solid #1E2D4A;
      object-fit: cover;
    }
    .content {
      padding: 1.75rem;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.4);
      color: #EF5350;
      font-size: 0.75rem;
      font-weight: 700;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      padding: 0.25rem 0.75rem;
      border-radius: 0.375rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .dot {
      width: 0.5rem;
      height: 0.5rem;
      border-radius: 9999px;
      background: #EF5350;
    }
    h1 {
      font-size: 1.25rem;
      font-weight: 700;
      color: #F8FAFC;
      margin-top: 0.75rem;
      line-height: 1.4;
    }
    p {
      font-size: 0.8125rem;
      color: #94A3B8;
      margin-top: 0.5rem;
      line-height: 1.5;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.75rem;
      margin-top: 1.25rem;
      background: #080D17;
      border: 1px solid #16233B;
      border-radius: 0.75rem;
      padding: 1rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.75rem;
    }
    .grid-item {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }
    .grid-full {
      grid-column: 1 / -1;
      padding-top: 0.5rem;
      border-top: 1px solid #16233B;
    }
    .label {
      color: #64748B;
      font-size: 0.65rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 600;
    }
    .val-sky { color: #38BDF8; font-weight: 600; }
    .val-emerald { color: #34D399; }
    .val-amber { color: #FBBF24; font-weight: 600; }
    .val-text { color: #CBD5E1; }
    .footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-top: 1.5rem;
      padding-top: 1rem;
      border-top: 1px solid #16233B;
      font-size: 0.75rem;
      color: #64748B;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: #152338;
      color: #E2E8F0;
      text-decoration: none;
      padding: 0.5rem 1rem;
      border-radius: 0.5rem;
      font-weight: 600;
      font-size: 0.75rem;
      border: 1px solid #1E2D4A;
      transition: background 0.15s ease;
    }
    .btn:hover {
      background: #1E2D4A;
      color: #FFFFFF;
    }
    @media (max-width: 640px) {
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="card">
    <img src="/assets/security/403-forbidden.jpg" alt="403 Forbidden - NUSANTARA-SMS" class="hero-img" />
    <div class="content">
      <div class="badge">
        <span class="dot"></span>
        403 — FORBIDDEN
      </div>
      <h1>Access denied by NUSANTARA-SMS Security Protection.</h1>
      <p>
        Permintaan Anda telah diinspeksi oleh mesin pertahanan siber NUSANTARA-SMS dan ditolak berdasarkan kebijakan penangkalan aktif.
      </p>

      <div class="grid">
        <div class="grid-item">
          <span class="label">Request ID:</span>
          <span class="val-sky">${safeReqId}</span>
        </div>
        <div class="grid-item">
          <span class="label">Timestamp:</span>
          <span class="val-emerald">${safeTime}</span>
        </div>
        <div class="grid-item grid-full">
          <span class="label">Detection Category:</span>
          <span class="val-amber">${safeCategory}</span>
        </div>
        <div class="grid-item grid-full">
          <span class="label">Enforcement Detail:</span>
          <span class="val-text">${safeReason}</span>
        </div>
      </div>

      <div class="footer">
        <span>NUSANTARA-SMS Defense Engine • Real Evidence Enforcement</span>
        <a href="/" class="btn">Kembali ke Beranda</a>
      </div>
    </div>
  </div>
</body>
</html>`;
}

// 403 Forbidden Preview Route (Section 6)
app.get('/403', (req: Request, res: Response) => {
  const requestId = (req.query.requestId as string) || (req as any).id || `REQ-${Date.now().toString().slice(-6)}-${crypto.randomBytes(3).toString('hex')}`;
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const category = (req.query.category as string) || 'Manual Suspicious Activity';
  const reason = (req.query.reason as string) || 'WAF Layer 7 inspection detected unpermitted attack signature.';

  res.status(403).send(renderForbidden403Html({
    requestId,
    timestamp,
    category,
    reason,
    clientIp: req.ip || '127.0.0.1',
  }));
});

// Protected Application Gateway (Section 6: Automatic 403 Response & Evidence Recording)
app.all('/protected/*', (req: Request, res: Response) => {
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || req.ip || '192.168.100.88';
  const rawUrl = req.originalUrl || req.url;
  const requestId = (req as any).id || `REQ-${Date.now().toString().slice(-6)}-${crypto.randomBytes(3).toString('hex')}`;
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);

  // 1. Check if client IP is actively blocked in Blocked IPs
  if (storage.isIpBlocked(clientIp)) {
    const blockedRecord = storage.getBlockedIps().find((b) => b.ipAddress === clientIp && b.blockStatus === 'ACTIVE');
    const reason = blockedRecord ? `IP address is actively blocked: ${blockedRecord.detectionReason}` : 'IP address is actively blocked by NUSANTARA-SMS enforcement.';

    if (req.accepts('html') && !req.headers.accept?.includes('application/json')) {
      return res.status(403).send(renderForbidden403Html({
        requestId,
        timestamp,
        category: 'Automated Suspicious Activity',
        reason,
        clientIp,
      }));
    }
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Access denied by NUSANTARA-SMS Security Protection.',
      requestId,
      timestamp,
      category: 'Automated Suspicious Activity',
      reason,
      status: 403,
    });
  }

  // 2. Evaluate request payload against Detection Engine
  const rawPayload = `${req.method} ${rawUrl} ${JSON.stringify(req.query || {})} ${JSON.stringify(req.body || {})}`;
  const evaluation = evaluateRequestPayload(rawPayload, rawUrl, req.method, req.headers as Record<string, string>);

  if (evaluation.matchedRule || evaluation.severity === 'high' || evaluation.severity === 'critical') {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const isAutomated =
      userAgent.includes('sqlmap') ||
      userAgent.includes('nikto') ||
      userAgent.includes('nmap') ||
      userAgent.includes('masscan') ||
      userAgent.includes('gobuster') ||
      userAgent.includes('dirb') ||
      userAgent.includes('python-requests');
    const category = isAutomated ? 'Automated Suspicious Activity' : 'Manual Suspicious Activity';
    const reason = `Aktivitas mencurigakan terdeteksi: ${evaluation.matchedRule?.name || evaluation.attackName} pada endpoint ${rawUrl.split('?')[0]}.`;

    // Record verified event in database
    const eventRes = storage.processIncomingEvent({
      source: 'Nusantara WAF',
      category: 'web_attack',
      rawPayload,
      sourceIp: clientIp,
      destIp: '192.168.100.75',
      destPort: 8081,
      protocol: 'HTTP',
      uri: rawUrl,
      method: req.method,
      defenseStatus: 'BLOCKED_BY_WAF',
      blockingProof: {
        isBlocked: true,
        httpStatus: 403,
        action: 'block',
        blockingMechanism: 'WAF',
        ruleId: evaluation.matchedRule?.id || 'CRS-942100',
        proofDetail: `HTTP 403 Forbidden emitted by NUSANTARA-SMS WAF for rule ${evaluation.matchedRule?.id || 'CRS'}`,
        evidenceReason: `${category}: ${evaluation.matchedRule?.name || evaluation.attackName}. Penolakan Layer 7 WAF.`,
        confidenceScore: 99,
        evidenceSource: 'waf_audit',
        verifiedAt: timestamp,
        rawEvidencePayload: rawPayload,
      },
      requestId,
      isSimulated: false,
    });

    // Auto-record blocked IP into management
    storage.recordBlockedIp({
      ipAddress: clientIp,
      reason: evaluation.matchedRule?.name || evaluation.attackName,
      eventId: eventRes.event.id,
      mechanism: 'WAF',
    });

    broadcastSse('security_event', eventRes.event);
    if (eventRes.alert) broadcastSse('security_alert', eventRes.alert);
    broadcastSse('blocked_ip_update', storage.getBlockedIps());

    if (req.accepts('html') && !req.headers.accept?.includes('application/json')) {
      return res.status(403).send(renderForbidden403Html({
        requestId,
        timestamp,
        category,
        reason,
        clientIp,
      }));
    }
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Access denied by NUSANTARA-SMS Security Protection.',
      requestId,
      timestamp,
      category,
      reason,
      status: 403,
    });
  }

  // 3. Benign request
  res.json({
    message: 'Request inspected and permitted through NUSANTARA-SMS gateway.',
    target: 'http://192.168.100.75:8081',
    status: 200,
    requestId,
  });
});

// Blocked IPs API (Section 5: Real Enforcement Evidence Only)
app.get('/api/blocked-ips', (req: Request, res: Response) => {
  res.json(storage.getBlockedIps());
});

app.post('/api/blocked-ips/unblock', authenticateAdmin, (req: Request, res: Response) => {
  const { ipAddress, reason } = req.body || {};
  if (!ipAddress || typeof ipAddress !== 'string') {
    return res.status(400).json({ error: 'Valid ipAddress required.' });
  }

  const success = storage.unblockIp(ipAddress, reason || 'Admin unblock request', 'Administrator');
  if (!success) {
    return res.status(404).json({ error: 'IP address not found or not actively blocked.' });
  }

  broadcastSse('blocked_ip_update', storage.getBlockedIps());
  res.json({
    success: true,
    message: `Alamat IP ${ipAddress} berhasil dibuka blokirnya.`,
    blockedIps: storage.getBlockedIps(),
  });
});

app.post('/api/blocked-ips/manual-block', authenticateAdmin, (req: Request, res: Response) => {
  const { ipAddress, reason, mechanism } = req.body || {};
  if (!ipAddress || typeof ipAddress !== 'string') {
    return res.status(400).json({ error: 'Valid ipAddress required.' });
  }

  const record = storage.recordBlockedIp({
    ipAddress,
    reason: reason || 'Admin manual defense block',
    mechanism: mechanism || 'ADMIN_MANUAL',
  });

  if (!record) {
    return res.status(400).json({ error: 'Cannot block loopback or internal target IP.' });
  }

  broadcastSse('blocked_ip_update', storage.getBlockedIps());
  res.json({
    success: true,
    message: `Alamat IP ${ipAddress} berhasil diblokir secara manual.`,
    record,
  });
});

// Dashboard Summary API — Enforces Zero Dummy Data Policy (Section 3: 4 Main Cards)
app.get('/api/dashboard/summary', (req: Request, res: Response) => {
  const events = storage.getEvents();
  const alerts = storage.getAlerts();
  const incidents = storage.getIncidents();
  const sensors = storage.getSensors();
  const dvwaSensor = sensors.find((s) => s.id === 'sensor-dvwa');

  const criticalAlerts = alerts.filter((a) => a.severity === 'critical').length;
  const highAlerts = alerts.filter((a) => a.severity === 'high').length;
  const mediumAlerts = alerts.filter((a) => a.severity === 'medium').length;
  const lowAlerts = alerts.filter((a) => a.severity === 'low').length;

  const blockedEvents = events.filter(
    (e) =>
      e.defenseStatus === 'BLOCKED_BY_WAF' ||
      e.defenseStatus === 'BLOCKED_BY_IPS' ||
      e.defenseStatus === 'BLOCKED_BY_APPLICATION' ||
      e.defenseStatus === 'BLOCKED'
  );
  const activeBlockedIps = storage.getBlockedIps().filter((b) => b.blockStatus === 'ACTIVE');
  const connectedSensorsCount = sensors.filter((s) => s.connectionStatus === 'connected').length;

  const isDegraded = sensors.some((s) => s.connectionStatus === 'degraded' || s.connectionStatus === 'disconnected');

  let monitoringState: 'NO_THREATS_DETECTED' | 'MONITORING_DEGRADED' | 'THREATS_DETECTED';
  let statusMessage: string;

  if (alerts.length > 0) {
    monitoringState = 'THREATS_DETECTED';
    statusMessage = `${alerts.length} verified security threats actively flagged on target asset.`;
  } else if (isDegraded || dvwaSensor?.connectionStatus !== 'connected') {
    monitoringState = 'MONITORING_DEGRADED';
    statusMessage = 'Monitoring Degraded — Sensor or target connection not fully established.';
  } else {
    monitoringState = 'NO_THREATS_DETECTED';
    statusMessage = 'Belum ada aktivitas ancaman yang terdeteksi.';
  }

  res.json({
    // Section 3: 4 Primary Cards
    totalDetectedThreats: alerts.length,
    successfullyBlocked: blockedEvents.length,
    blockedIps: activeBlockedIps.length,
    connectedSensors: connectedSensorsCount,
    // Compatibility fields
    totalDetectedAttacks: alerts.length,
    totalEvents: events.length,
    criticalAlerts,
    highAlerts,
    mediumAlerts,
    lowAlerts,
    activeIncidents: incidents.filter((i) => i.status !== 'closed').length,
    monitoringState,
    statusMessage,
    targetAsset: 'http://192.168.100.75:8081',
    dvwaStatus: dvwaSensor?.connectionStatus || 'disconnected',
    sensorSummary: {
      suricata: sensors.find((s) => s.id === 'sensor-suricata')?.connectionStatus || 'waiting_telemetry',
      dvwa: dvwaSensor?.connectionStatus || 'disconnected',
      waf: sensors.find((s) => s.id === 'sensor-waf')?.connectionStatus || 'waiting_telemetry',
      database: 'connected',
      stream: 'connected',
    },
  });
});

// Security Alerts API (Deduplicated & Correlated Alerts with Evidence)
app.get('/api/alerts', (req: Request, res: Response) => {
  res.json(storage.getAlerts());
});

// Raw Events API
app.get('/api/events', (req: Request, res: Response) => {
  const { category, severity, limit, search } = req.query;
  let results = storage.getEvents();

  if (category && typeof category === 'string' && category !== 'all') {
    results = results.filter((e) => e.category === category);
  }
  if (severity && typeof severity === 'string' && severity !== 'all') {
    results = results.filter((e) => e.severity === severity);
  }
  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    results = results.filter(
      (e) =>
        e.title.toLowerCase().includes(q) ||
        e.sourceIp.includes(q) ||
        e.destIp.includes(q) ||
        e.mitreTechniqueId.toLowerCase().includes(q)
    );
  }

  const max = limit ? parseInt(limit as string, 10) : 100;
  res.json(results.slice(0, max));
});

// Incidents API
app.get('/api/incidents', (req: Request, res: Response) => {
  res.json(storage.getIncidents());
});

app.patch('/api/incidents/:id/status', (req: Request, res: Response) => {
  const { status, note } = req.body;
  const inc = storage.getIncidents().find((i) => i.id === req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });

  inc.status = status;
  inc.updatedAt = new Date().toISOString().replace('T', ' ').slice(0, 19);

  if (note) {
    inc.timeline.push({
      step: `Status changed to ${status}`,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      status: 'completed',
      note,
    });
  }

  storage.saveDatabase();
  broadcastSse('incident_update', inc);

  res.json(inc);
});

// Network Topology & Monitored Assets API
app.get('/api/network-topology', (req: Request, res: Response) => {
  res.json(storage.getAssets());
});

app.patch('/api/network-topology/node/:id/isolate', (req: Request, res: Response) => {
  const node = storage.getAssets().find((n) => n.id === req.params.id);
  if (!node) return res.status(404).json({ error: 'Node not found' });

  node.status = node.status === 'isolated' ? 'normal' : 'isolated';
  storage.saveDatabase();

  broadcastSse('node_update', node);
  res.json(node);
});

// Sensors and Connectors Status API
app.get('/api/sensors', (req: Request, res: Response) => {
  res.json(storage.getSensors());
});

// On-Demand Probe for DVWA target health
app.post('/api/dvwa/probe-health', async (req: Request, res: Response) => {
  const result = await storage.probeDvwaTarget();
  broadcastSse('sensor_update', storage.getSensors());
  res.json(result);
});

// Audit Logs API
app.get('/api/audit-logs', (req: Request, res: Response) => {
  res.json(storage.getAuditLogs());
});

// MITRE ATT&CK Matrix Dynamic Telemetry Endpoint
app.get('/api/mitre', (req: Request, res: Response) => {
  const alerts = storage.getAlerts();
  const events = storage.getEvents();

  const getDetectionsForTechnique = (techId: string) => {
    const matchedAlerts = alerts.filter(
      (a) => (a.mitreTechniqueId || '').toUpperCase().includes(techId.toUpperCase())
    );
    const matchedEvents = events.filter(
      (e) => (e.mitreTechniqueId || '').toUpperCase().includes(techId.toUpperCase())
    );
    const count = matchedAlerts.length + matchedEvents.length;
    return {
      detectionCount: count,
      status: (count > 0 ? 'detected' : 'covered') as 'detected' | 'covered',
    };
  };

  const rawTactics = [
    {
      id: 'TA0001',
      name: 'Initial Access',
      shortName: 'Init Access',
      techniques: [
        {
          id: 'T1190',
          name: 'Exploit Public-Facing Application',
          tactic: 'Initial Access',
          tacticId: 'TA0001',
          description: 'Adversary executes unauthorized actions against DVWA web services (SQLi, XSS, etc.).',
          defensiveControls: ['ModSecurity CRS-942100', 'WAF Input Normalization', 'Fail2ban Port 8081'],
          ...getDetectionsForTechnique('T1190'),
        },
        {
          id: 'T1078',
          name: 'Valid Accounts',
          tactic: 'Initial Access',
          tacticId: 'TA0001',
          description: 'Compromise or abuse of default DVWA credentials (admin / password).',
          defensiveControls: ['Credential Complexity Enforcer', 'Brute-Force Lockout'],
          ...getDetectionsForTechnique('T1078'),
        },
      ],
    },
    {
      id: 'TA0002',
      name: 'Execution',
      shortName: 'Execution',
      techniques: [
        {
          id: 'T1059.004',
          name: 'Unix Shell',
          tactic: 'Execution',
          tacticId: 'TA0002',
          description: 'Adversary abuses Command Injection in DVWA to spawn /bin/sh or /bin/bash.',
          defensiveControls: ['Linux Kernel AppArmor / SELinux', 'Auditd Execve Watchdog', 'WAF CRS-932100'],
          ...getDetectionsForTechnique('T1059'),
        },
      ],
    },
    {
      id: 'TA0003',
      name: 'Persistence',
      shortName: 'Persistence',
      techniques: [
        {
          id: 'T1505.003',
          name: 'Web Shell',
          tactic: 'Persistence',
          tacticId: 'TA0003',
          description: 'Upload of malicious PHP script to /hackable/uploads/ to retain backdoor access.',
          defensiveControls: ['FIM Syscheck Inotify', 'Apache Noexec Directory Override', 'MIME Type Signature Check'],
          ...getDetectionsForTechnique('T1505'),
        },
      ],
    },
    {
      id: 'TA0005',
      name: 'Defense Evasion',
      shortName: 'Evasion',
      techniques: [
        {
          id: 'T1027',
          name: 'Obfuscated Files or Information',
          tactic: 'Defense Evasion',
          tacticId: 'TA0005',
          description: 'URL encoding (%252f), double encoding, or comment stripping to bypass WAF signatures.',
          defensiveControls: ['Deep URI Normalizer (CRS-901)', 'Entropy Evaluator'],
          ...getDetectionsForTechnique('T1027'),
        },
      ],
    },
    {
      id: 'TA0006',
      name: 'Credential Access',
      shortName: 'Cred Access',
      techniques: [
        {
          id: 'T1110',
          name: 'Brute Force',
          tactic: 'Credential Access',
          tacticId: 'TA0006',
          description: 'Systematic password guessing attacks on DVWA /vulnerabilities/brute/.',
          defensiveControls: ['IP Connection Rate Limiter', 'Captcha Challenge', 'Suricata Signature 2001211'],
          ...getDetectionsForTechnique('T1110'),
        },
      ],
    },
    {
      id: 'TA0007',
      name: 'Discovery',
      shortName: 'Discovery',
      techniques: [
        {
          id: 'T1083',
          name: 'File and Directory Discovery',
          tactic: 'Discovery',
          tacticId: 'TA0007',
          description: 'Directory traversal (../../../../etc/passwd) or reconnaissance automated scanners.',
          defensiveControls: ['CRS-930100 LFI/RFI Enforcer', 'Real-time 404 Threshold Monitor'],
          ...getDetectionsForTechnique('T1083'),
        },
      ],
    },
    {
      id: 'TA0011',
      name: 'Command and Control',
      shortName: 'C2',
      techniques: [
        {
          id: 'T1071.001',
          name: 'Web Protocols (HTTP/S C2)',
          tactic: 'Command and Control',
          tacticId: 'TA0011',
          description: 'Outbound beaconing or reverse shell connection to external C2 listeners.',
          defensiveControls: ['Suricata EVE Flow Tracker', 'Outbound Egress Port 8081 Lock'],
          ...getDetectionsForTechnique('T1071'),
        },
      ],
    },
  ];

  res.json({
    tactics: rawTactics,
    matrixVersion: '14.1-DEFENSIVE',
    totalAttacksMapped: alerts.length,
  });
});

// Threat Intelligence IOC Lookup API
app.post('/api/threat-intel/lookup', (req: Request, res: Response) => {
  const { query } = req.body;
  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: 'Query parameter required' });
  }

  const q = query.trim().toLowerCase();
  const alerts = storage.getAlerts();
  const events = storage.getEvents();

  // Check if query matches any actual attacking IP or payload in storage
  const matchedAlert = alerts.find(
    (a) =>
      a.sourceIp.toLowerCase().includes(q) ||
      a.attackName.toLowerCase().includes(q) ||
      a.evidenceReference.toLowerCase().includes(q)
  );

  const matchedEvent = events.find(
    (e) =>
      e.sourceIp.toLowerCase().includes(q) ||
      e.rawPayload?.toLowerCase().includes(q)
  );

  if (matchedAlert || matchedEvent) {
    return res.json({
      evaluatedQuery: query,
      reputation: 'malicious',
      note: 'Matched verified offensive activity observed against DVWA target (192.168.100.75:8081).',
      ioc: {
        indicator: query,
        confidenceScore: 98,
        threatActor: 'External Threat Actor / Penetration Probe',
        associatedMalware: matchedAlert?.attackName || 'Exploit Payload',
        feedSource: matchedAlert?.detectionSource || 'Nusantara-SMS Actual Telemetry',
        lastUpdated: matchedAlert?.lastSeen || new Date().toISOString().slice(0, 19),
      },
    });
  }

  res.json({
    evaluatedQuery: query,
    reputation: 'benign',
    note: 'No malicious activity observed for this indicator in target telemetry.',
    ioc: null,
  });
});

// -------------------------------------------------------------
// EVENT INGESTION & EXTERNAL TESTER PIPELINE (Collector Authenticated)
// -------------------------------------------------------------

// Administrator Authorization Middleware (Prioritas 1: Administrator privilege validation)
function authenticateAdmin(req: Request, res: Response, next: NextFunction) {
  const adminToken = (req.headers['x-admin-token'] as string) || (req.headers['authorization'] as string);

  if (!StorageEngine.validateAdminToken(adminToken)) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Administrator authorization required. Provide valid X-Admin-Token or Authorization Bearer header.',
      requestId: (req as any).id,
    });
  }
  next();
}

// Collector Authentication Middleware (Prioritas 1: No loopback bypass in production, constant-time & replay protected)
function authenticateCollector(req: Request, res: Response, next: NextFunction) {
  const token = (req.headers['x-collector-token'] as string) || (req.headers['authorization'] as string);

  if (!StorageEngine.validateCollectorToken(token)) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'A valid X-Collector-Token or Authorization Bearer header is required.',
      requestId: (req as any).id,
    });
  }

  // Replay Attack Protection: Check timestamp & nonce
  const reqTimestamp = req.headers['x-request-timestamp'] as string;
  const reqNonce = req.headers['x-request-nonce'] as string;
  if (reqTimestamp) {
    const replayCheck = storage.validateReplayProtection(reqTimestamp, reqNonce);
    if (!replayCheck.valid) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Replay Protection rejected request: ${replayCheck.reason}`,
        requestId: (req as any).id,
      });
    }
  }

  next();
}

// Token Rotation Endpoint (Prioritas 1: Restricted to Administrators Only)
app.post('/api/collector/rotate-token', authenticateAdmin, (req: Request, res: Response) => {
  const newToken = StorageEngine.rotateCollectorToken();
  const rotatedAt = new Date().toISOString();
  res.json({
    success: true,
    message: 'Collector authentication credential rotated successfully by administrator.',
    newToken,
    rotatedAt,
    hint: 'Update your Ubuntu forwarder daemon with the new token or restart the forwarder script.',
  });
});

// Sanitized Token Metadata (Prioritas 1: Production Readiness - Minimal disclosure)
app.get('/api/collector/token-info', (req: Request, res: Response) => {
  const activeToken = StorageEngine.getCollectorAuthToken();
  res.json({
    active: true,
    maskedToken: activeToken.slice(0, 4) + '...' + activeToken.slice(-4),
    tokenLength: activeToken.length,
    isEnvDefined: !!process.env.COLLECTOR_TOKEN,
  });
});

// Collector Connectivity Heartbeat (Checks if Ubuntu Server forwarder is active)
app.post('/api/collector/heartbeat', authenticateCollector, (req: Request, res: Response) => {
  const { version, suricataActive, wafActive, apacheActive } = req.body || {};
  const collectorIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || req.ip || '192.168.100.75';

  const status = storage.recordCollectorHeartbeat({
    collectorIp,
    version: version || '1.2.0-collector',
    suricataActive: suricataActive !== undefined ? suricataActive : true,
    wafActive: wafActive !== undefined ? wafActive : true,
    apacheActive: apacheActive !== undefined ? apacheActive : true,
  });

  broadcastSse('collector_heartbeat', status);
  res.json({ success: true, status });
});

// Collector Status Query API
app.get('/api/collector/status', (req: Request, res: Response) => {
  res.json(storage.getCollectorStatus());
});

// External Tester (Kali Linux) Session Telemetry
app.get('/api/collector/external-tester', (req: Request, res: Response) => {
  res.json(storage.getExternalTesterSession());
});

// Ingest from Suricata EVE JSON (Priority 1: External Tester Network Packet Stream)
app.post('/api/ingest/suricata', authenticateCollector, (req: Request, res: Response) => {
  const rawBody = req.body;

  if (!rawBody) {
    return res.status(400).json({ error: 'No EVE JSON payload provided' });
  }

  // Handle single object or array of lines
  const events = Array.isArray(rawBody) ? rawBody : [rawBody];
  const results = [];

  for (const item of events) {
    const outcome = storage.processSuricataEveJson(item);
    if (outcome.success && outcome.event) {
      results.push(outcome);
      broadcastSse('security_event', outcome.event);
      if (outcome.alert) {
        broadcastSse('security_alert', outcome.alert);
      }
    }
  }

  // Audit log for received batch
  storage.getAuditLogs().unshift({
    id: `AUD-COLLECT-${Date.now().toString().slice(-4)}`,
    timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
    user: 'Ubuntu Collector Daemon',
    action: 'INGEST_SURICATA_BATCH',
    target: `${events.length} EVE event(s)`,
    outcome: 'success',
    ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || req.ip || '192.168.100.75',
  });

  res.json({
    success: true,
    processedCount: events.length,
    alertsCreated: results.length,
    message: `Ingested ${events.length} Suricata events from collector.`,
  });
});

// Ingest from Apache Access Log (Priority 3: Actual DVWA HTTP Access Logs)
app.post('/api/ingest/apache', authenticateCollector, (req: Request, res: Response) => {
  const { lines, line } = req.body;
  const rawLines: string[] = lines ? (Array.isArray(lines) ? lines : [lines]) : line ? [line] : [];

  if (rawLines.length === 0) {
    return res.status(400).json({ error: 'Payload lines required (Apache access log string array).' });
  }

  const collectorIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || req.ip || '192.168.100.75';
  const results = [];

  for (const logLine of rawLines) {
    const outcome = storage.processApacheAccessLogLine(logLine, collectorIp);
    if (outcome.success && outcome.event) {
      results.push(outcome);
      broadcastSse('security_event', outcome.event);
      if (outcome.alert) {
        broadcastSse('security_alert', outcome.alert);
      }
    }
  }

  res.json({
    success: true,
    processedCount: rawLines.length,
    resultsCount: results.length,
    message: `Processed ${rawLines.length} Apache log lines.`,
  });
});

// Ingest from WAF Reverse Proxy / Ingress Engine (Priority 2)
app.post(['/api/ingest/waf', '/api/ingest/dvwa'], authenticateCollector, (req: Request, res: Response) => {
  const { payload, uri, method, sourceIp, headers, statusCode, isBlocked, ruleId } = req.body;

  if (!payload && !uri) {
    return res.status(400).json({ error: 'Request payload or URI required for evaluation.' });
  }

  const clientIp = sourceIp || req.ip || '192.168.100.88';
  const isHttp403 = statusCode === 403 || isBlocked === true;

  const { event, alert, isNewAlert } = storage.processIncomingEvent({
    source: 'Nusantara WAF',
    category: 'web_attack',
    rawPayload: typeof payload === 'object' ? JSON.stringify(payload) : payload || uri,
    sourceIp: clientIp,
    destIp: '192.168.100.75',
    destPort: 8081,
    protocol: 'HTTP',
    uri: uri || '/',
    method: method || 'GET',
    headers: {
      ...(headers || {}),
      status: String(statusCode || (isHttp403 ? 403 : 200)),
      'x-blocked': isHttp403 ? 'true' : 'false',
    },
    defenseStatus: isHttp403 ? 'BLOCKED_BY_WAF' : 'ALLOWED',
    blockingProof: {
      isBlocked: isHttp403,
      blockingMechanism: isHttp403 ? 'WAF' : 'NONE',
      httpStatus: statusCode || (isHttp403 ? 403 : 200),
      action: isHttp403 ? 'block' : 'allowed',
      ruleId: ruleId || (isHttp403 ? 'CRS-942100' : undefined),
      proofDetail: isHttp403
        ? 'WAF Inline Engine dropped attack and issued HTTP 403 Forbidden'
        : 'WAF IDS Mode: Attack signature recognized, but passed through to DVWA',
      verifiedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
    },
    collectorMetadata: {
      sourceFeed: 'waf',
      isExternalTester: clientIp !== '127.0.0.1' && clientIp !== '192.168.100.75',
      testerIdentifier: 'Kali Linux External Tester',
      ingestedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
    },
    isSimulated: false,
  });

  broadcastSse('security_event', event);
  if (alert) {
    broadcastSse('security_alert', alert);
  }

  res.json({
    success: true,
    event,
    alert,
    isNewAlert,
    defenseStatus: event.defenseStatus,
    blockingProof: event.blockingProof,
  });
});

// Internal Engine Unit Test Simulation (STRICTLY ISOLATED FROM REAL KALI LINUX TELEMETRY)
// This endpoint is solely for testing local pattern matching and does NOT simulate external network packets
app.post('/api/test/dvwa-probe', async (req: Request, res: Response) => {
  const { testType, customPayload } = req.body;
  const targetHost = 'http://192.168.100.75:8081';

  let uri = '/vulnerabilities/sqli/';
  let payload = customPayload || "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables-- -";
  let method = 'GET';

  if (testType === 'sqli') {
    uri = `/vulnerabilities/sqli/?id=${encodeURIComponent(payload)}&Submit=Submit`;
  } else if (testType === 'xss') {
    uri = `/vulnerabilities/xss_r/?name=${encodeURIComponent(customPayload || '<script>alert("Nusantara-Defense")</script>')}`;
    payload = customPayload || '<script>alert("Nusantara-Defense")</script>';
  } else if (testType === 'cmdi') {
    uri = `/vulnerabilities/exec/`;
    method = 'POST';
    payload = `ip=${encodeURIComponent('127.0.0.1; cat /etc/passwd')}&Submit=Submit`;
  } else if (testType === 'traversal') {
    uri = `/vulnerabilities/fi/?page=../../../../etc/passwd`;
    payload = '../../../../etc/passwd';
  } else if (testType === 'clean') {
    uri = `/index.php`;
    payload = 'GET /index.php HTTP/1.1';
  }

  // Attempt real probe connection to DVWA
  let targetResponseStatus = 'unreachable';
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const probeRes = await fetch(`${targetHost}${uri}`, {
      method,
      signal: controller.signal,
      headers: { 'User-Agent': 'Nusantara-Internal-Unit-Validator/1.0' },
    });
    clearTimeout(timeout);
    targetResponseStatus = `${probeRes.status} ${probeRes.statusText}`;
  } catch (err: any) {
    targetResponseStatus = `Target unreachable from cloud container: ${err.message}`;
  }

  // Evaluate the payload through the engine labeled strictly as SIMULATION
  const { event, alert, isNewAlert } = storage.processIncomingEvent({
    source: 'Internal Simulation',
    category: 'web_attack',
    rawPayload: `[INTERNAL SIMULATION] ${payload}`,
    sourceIp: '127.0.0.1 (Local Unit Simulator)',
    destIp: '192.168.100.75',
    destPort: 8081,
    protocol: 'HTTP',
    uri,
    method,
    defenseStatus: 'ALLOWED',
    blockingProof: {
      isBlocked: false,
      blockingMechanism: 'NONE',
      httpStatus: 200,
      action: 'allowed',
      proofDetail: 'Unit Test Simulation Only: Internal engine pattern matcher test (NOT an external Kali Linux packet).',
      verifiedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
    },
    collectorMetadata: {
      sourceFeed: 'simulation',
      isExternalTester: false,
      testerIdentifier: 'Internal Unit Tester (Simulated)',
      ingestedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
    },
    isSimulated: true, // Flagged clearly as simulation to satisfy architectural separation
  });

  broadcastSse('security_event', event);
  if (alert) {
    broadcastSse('security_alert', alert);
  }

  res.json({
    success: true,
    isSimulation: true,
    provenance: 'INTERNAL_UNIT_TEST_ONLY',
    warning: 'SIMULATION ONLY: This test was generated locally for rule validation and did NOT originate from external Kali Linux.',
    testType,
    targetResponseStatus,
    evaluatedEvent: event,
    generatedAlert: alert,
    isNewAlert,
  });
});

// Reset Database to Clean State (Test A acceptance test!)
app.post('/api/pipeline/reset', (req: Request, res: Response) => {
  storage.clearAllData();
  broadcastSse('pipeline_reset', { message: 'Database reset to zero state.' });
  res.json({
    success: true,
    message: 'Pipeline reset to clean state (0 attacks, 0 alerts, 0 events).',
    alerts: 0,
    events: 0,
  });
});

// Collector Script for Ubuntu Home Server (Prioritas 1: Zero Secret Leakage)
app.get('/api/collector/script', (req: Request, res: Response) => {
  const appUrl = process.env.APP_URL || `http://${req.headers.host}`;
  const isConfiguredRequested = req.query.configured === 'true';

  let scriptToken = '${COLLECTOR_TOKEN:-<PASTE_YOUR_COLLECTOR_TOKEN_HERE>}';

  if (isConfiguredRequested) {
    const adminToken = (req.headers['x-admin-token'] as string) || (req.headers['authorization'] as string);
    if (!StorageEngine.validateAdminToken(adminToken)) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Administrator authorization required to download pre-configured script. Provide valid X-Admin-Token header.',
        requestId: (req as any).id,
      });
    }
    // Only authorized administrator receives active token in downloaded script
    scriptToken = StorageEngine.getCollectorAuthToken();
  }

  const script = `#!/usr/bin/env bash
# ==============================================================================
# NUSANTARA-SMS — Ubuntu Home Server Forwarder Daemon
# Target: DVWA (192.168.100.75:8081)
# Forwards Suricata EVE JSON, Apache Access Logs, and Heartbeat with Auth Token
# Hardened: Zero Credential Leakage, Replay Attack Protection, Log Rotation Tolerance
# ==============================================================================

SERVER_ENDPOINT="${appUrl}"
COLLECTOR_TOKEN="${scriptToken}"
SURICATA_LOG="/var/log/suricata/eve.json"
APACHE_LOG="/var/log/apache2/access.log"

echo "[NUSANTARA-SMS] Starting Authenticated Collector for Ubuntu Home Server..."
echo "  Target Server: $SERVER_ENDPOINT"
echo "  Replay Protection: Enabled (Timestamp + Nonce Tracking)"

if [ "$COLLECTOR_TOKEN" = "<PASTE_YOUR_COLLECTOR_TOKEN_HERE>" ]; then
  echo "[!] ERROR: COLLECTOR_TOKEN has not been configured!"
  echo "    Please export COLLECTOR_TOKEN=\"your-token\" before running, or edit this script."
  exit 1
fi

get_nonce() {
  head -c 16 /dev/urandom | xxd -p | head -n 1 2>/dev/null || od -N 8 -tx1 /dev/urandom | head -1 | tr -d ' '
}

# Background Heartbeat Loop (every 30 seconds)
(
  while true; do
    TS=$(date +%s)
    NONCE=$(get_nonce)
    curl -s -X POST "$SERVER_ENDPOINT/api/collector/heartbeat" \\
      -H "Content-Type: application/json" \\
      -H "X-Collector-Token: $COLLECTOR_TOKEN" \\
      -H "X-Request-Timestamp: $TS" \\
      -H "X-Request-Nonce: $NONCE" \\
      -d '{"version":"1.2.0-collector","suricataActive":true,"apacheActive":true}' > /dev/null
    sleep 30
  done
) &
HEARTBEAT_PID=$!
echo "[+] Heartbeat daemon started (PID: $HEARTBEAT_PID)"

# Stream Suricata EVE JSON with log-rotation tolerance (--retry)
if [ -f "$SURICATA_LOG" ]; then
  echo "[+] Tailing Suricata EVE log: $SURICATA_LOG"
  tail -F --retry "$SURICATA_LOG" 2>/dev/null | while read -r line; do
    TS=$(date +%s)
    NONCE=$(get_nonce)
    curl -s -X POST "$SERVER_ENDPOINT/api/ingest/suricata" \\
      -H "Content-Type: application/json" \\
      -H "X-Collector-Token: $COLLECTOR_TOKEN" \\
      -H "X-Request-Timestamp: $TS" \\
      -H "X-Request-Nonce: $NONCE" \\
      -d "$line" > /dev/null
  done
else
  echo "[!] Suricata log not found ($SURICATA_LOG). Falling back to Apache access log..."
  tail -F --retry "$APACHE_LOG" 2>/dev/null | while read -r line; do
    TS=$(date +%s)
    NONCE=$(get_nonce)
    curl -s -X POST "$SERVER_ENDPOINT/api/ingest/apache" \\
      -H "Content-Type: application/json" \\
      -H "X-Collector-Token: $COLLECTOR_TOKEN" \\
      -H "X-Request-Timestamp: $TS" \\
      -H "X-Request-Nonce: $NONCE" \\
      -d "{\\"line\\": \\"$line\\"}" > /dev/null
  done
fi
`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(script);
});

// External Tester (Kali Linux) Attack Recipes Guide
app.get('/api/collector/kali-guide', (req: Request, res: Response) => {
  const guide = `# ==============================================================================
# NUSANTARA-SMS — External Kali Linux Testing Cheatsheet
# Execute these commands directly ON YOUR KALI LINUX MACHINE
# Target DVWA Host: http://192.168.100.75:8081
# ==============================================================================

# 1. SQL Injection Test via curl (Union-based extraction):
curl -s -G "http://192.168.100.75:8081/vulnerabilities/sqli/" \\
  --data-urlencode "id=1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -" \\
  --data-urlencode "Submit=Submit" \\
  -H "Cookie: security=low; PHPSESSID=kalitest123"

# 2. Automated SQL Injection via sqlmap:
sqlmap -u "http://192.168.100.75:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \\
  --cookie="security=low; PHPSESSID=kalitest123" \\
  --batch --dbs

# 3. Cross-Site Scripting (Reflected XSS):
curl -s -G "http://192.168.100.75:8081/vulnerabilities/xss_r/" \\
  --data-urlencode 'name=<script>alert("NUSANTARA-DEFENSE-PROVEN")</script>' \\
  -H "Cookie: security=low; PHPSESSID=kalitest123"

# 4. OS Command Injection:
curl -s -X POST "http://192.168.100.75:8081/vulnerabilities/exec/" \\
  -d "ip=127.0.0.1; cat /etc/passwd&Submit=Submit" \\
  -H "Cookie: security=low; PHPSESSID=kalitest123"

# 5. Directory Traversal / LFI:
curl -s "http://192.168.100.75:8081/vulnerabilities/fi/?page=../../../../etc/passwd" \\
  -H "Cookie: security=low; PHPSESSID=kalitest123"
`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(guide);
});

// AI Security Analyst API — Real Data Only (Zero Hallucination)
app.post('/api/ai/analyze-incident', async (req: Request, res: Response) => {
  const alerts = storage.getAlerts();
  const incidents = storage.getIncidents();
  const events = storage.getEvents();

  // If there are zero events/alerts in database, strictly enforce Zero Dummy Data response:
  if (alerts.length === 0 && events.length === 0) {
    return res.json({
      analysis: '### Status Analisis: Bersih (Zero Threats)\n\nBelum terdapat security event yang dapat dianalisis. Sistem saat ini dalam status bersih tanpa ancaman aktif pada target **DVWA (192.168.100.75:8081)**.',
      modelUsed: 'Nusantara-ZeroData-Enforcer',
      timestamp: new Date().toISOString(),
    });
  }

  const { incidentId, userPrompt } = req.body;
  const inc = incidents.find((i) => i.id === incidentId) || incidents[0];
  const relevantAlerts = alerts.slice(0, 5);

  const systemInstruction = `You are the Level 3 Senior SOC Analyst for the NUSANTARA-SMS platform.
Analyze ONLY verified actual events and evidence present in the telemetry database.
Target Asset under protection: DVWA (192.168.100.75:8081).
Never invent fake CVEs, fake IPs, or fake attack vectors. If evidence is limited, state "Bukti belum mencukupi untuk memastikan jenis ancaman".
Structure your response in Markdown:
1. Threat Overview & Attribution based strictly on evidence
2. Observed Evidence & Request Payloads
3. MITRE ATT&CK & OWASP Mapping
4. Immediate Mitigation Directives for Ubuntu/DVWA`;

  const promptContent = `Target Asset: DVWA (192.168.100.75:8081)
Active Alerts Count: ${alerts.length}
Alerts Evidence: ${JSON.stringify(relevantAlerts.map((a) => ({ name: a.attackName, rule: a.detectionRule, ip: a.sourceIp, evidence: a.evidenceReference })))}
Incident Title: ${inc?.title || 'None'}
Analyst Query: ${userPrompt || 'Perform technical triage on verified alerts.'}`;

  try {
    if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY') {
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI Request Timeout')), 4500)
      );

      const aiPromise = ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: promptContent,
        config: { systemInstruction },
      });

      const response = await Promise.race([aiPromise, timeoutPromise]);

      return res.json({
        analysis: response.text,
        modelUsed: 'gemini-3.8-flash',
        timestamp: new Date().toISOString(),
      });
    }
  } catch (error) {
    console.warn('Gemini API call timed out or failed; engaging SOC heuristic engine:', error);
  }

  // Fallback heuristic analysis strictly referencing real alerts
  const fallbackAnalysis = `### 1. Threat Overview & Evidence Analysis
Target: **DVWA on 192.168.100.75:8081**
Total verified alerts in database: **${alerts.length}**.
Latest Alert: **${relevantAlerts[0]?.attackName || 'Anomalous Request'}** from IP **${relevantAlerts[0]?.sourceIp || 'Unknown'}**.

### 2. Request Evidence
* **Rule Matched**: ${relevantAlerts[0]?.detectionRule || 'N/A'}
* **Extracted Evidence**: \`${relevantAlerts[0]?.evidenceReference || 'N/A'}\`

### 3. MITRE ATT&CK & OWASP Mapping
* **MITRE ATT&CK**: ${relevantAlerts[0]?.mitreTechniqueId || 'T1190'} (${relevantAlerts[0]?.mitreTechniqueName || 'Exploit Public-Facing Application'})
* **OWASP**: ${relevantAlerts[0]?.owaspCategory || 'A03:2021-Injection'}

### 4. Immediate Mitigation
1. Review DVWA security level in \`/var/www/html/dvwa/config/config.inc.php\`.
2. Apply firewall rate limiting on attacking IP: \`iptables -A INPUT -s ${relevantAlerts[0]?.sourceIp || '192.168.100.1'} -j DROP\`.
3. Enable ModSecurity WAF rule engine on the Ubuntu Home Server.`;

  return res.json({
    analysis: fallbackAnalysis,
    modelUsed: 'Nusantara-SOC-Engine (Real Evidence)',
    timestamp: new Date().toISOString(),
  });
});

// Interactive AI SOC Chat
app.post('/api/ai/chat', async (req: Request, res: Response) => {
  const alerts = storage.getAlerts();
  const { message } = req.body;

  if (alerts.length === 0) {
    return res.json({
      reply: 'Saat ini belum terdapat security event atau alert pada target **DVWA (192.168.100.75:8081)**. Sistem dalam status bersih ("NO SECURITY THREATS DETECTED").',
    });
  }

  try {
    if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY') {
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI Request Timeout')), 4500)
      );

      const aiPromise = ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: `Target: DVWA (192.168.100.75:8081). Real Alerts: ${alerts.length} active. Latest: ${alerts[0]?.attackName}. Question: ${message}`,
        config: {
          systemInstruction: 'You are the AI SOC Analyst for Nusantara-SMS. Analyze ONLY real evidence from DVWA. Be concise and authoritative.',
        },
      });

      const response = await Promise.race([aiPromise, timeoutPromise]);
      return res.json({ reply: response.text });
    }
  } catch (error) {
    console.warn('AI Chat Error; engaging heuristic fallback:', error);
  }

  return res.json({
    reply: `**[Nusantara AI SOC Analyst]**: Berdasarkan ${alerts.length} alert aktual pada target **192.168.100.75:8081**, ancaman utama saat ini adalah **${alerts[0]?.attackName}** dari IP **${alerts[0]?.sourceIp}**. Bukti payload: \`${alerts[0]?.evidenceReference.slice(0, 50)}\`.`,
  });
});

// Global Sanitized Error Handler (Prioritas 1: Suppress internal stack traces)
app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
  const reqId = (req as any).id || 'N/A';
  console.error(`[NUSANTARA-SMS Error] [ReqID: ${reqId}] ${err?.message || err}`);
  if (!res.headersSent) {
    res.status(err.status || 500).json({
      error: 'Security Engine Error',
      message: process.env.NODE_ENV === 'production' 
        ? 'A protected internal server event occurred. Details logged securely.'
        : (err?.message || 'Internal Server Error'),
      requestId: reqId,
      timestamp: new Date().toISOString(),
    });
  }
});

// -------------------------------------------------------------
// Serve Frontend with Vite in Dev, or Static in Production
// -------------------------------------------------------------

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  server.listen(PORT, () => {
    console.log(`[NUSANTARA-SMS] Defensive Cyber Platform running at http://localhost:${PORT}`);
    console.log(`[NUSANTARA-SMS] Monitored Target: DVWA (http://192.168.100.75:8081)`);
    console.log(`[NUSANTARA-SMS] Ingestion API: POST http://localhost:${PORT}/api/ingest/suricata`);
    console.log(`[NUSANTARA-SMS] Forwarder Script: GET http://localhost:${PORT}/api/collector/script`);
  });
}

// Graceful Shutdown Handler (Prioritas 4: ACID persistence & clean connection termination)
function gracefulShutdown(signal: string) {
  console.log(`\n[NUSANTARA-SMS] Received ${signal}. Initiating graceful shutdown...`);
  clearInterval(sseKeepAliveInterval);

  for (const client of sseClients) {
    try {
      client.end();
    } catch {}
  }
  sseClients.clear();

  server.close(() => {
    console.log('[NUSANTARA-SMS] HTTP/SSE server successfully closed.');
    process.exit(0);
  });

  setTimeout(() => {
    console.error('[NUSANTARA-SMS] Graceful shutdown timed out; forced exit.');
    process.exit(1);
  }, 5000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

startServer().catch((err) => {
  console.error('[NUSANTARA-SMS] Failed to start server:', err);
});
