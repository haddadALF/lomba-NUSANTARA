/**
 * NUSANTARA-SMS — HTTP API Hardening & Acceptance Test Suite
 * Priority 1: Collector Security (Token Leak Prevention, Admin Authorization, No Loopback Bypass)
 * Priority 4: Sensor State & Monitoring Transparency (/api/health component breakdown)
 */

import http from 'http';
import { StorageEngine } from '../src/db/storage.js';

interface ApiTestResult {
  name: string;
  category: string;
  passed: boolean;
  detail: string;
}

const results: ApiTestResult[] = [];

function record(name: string, category: string, passed: boolean, detail: string) {
  results.push({ name, category, passed, detail });
  const statusStr = passed ? '[\x1b[32mPASS\x1b[0m]' : '[\x1b[31mFAIL\x1b[0m]';
  console.log(`${statusStr} [${category}] ${name}: ${detail}`);
}

function makeRequest(options: http.RequestOptions, bodyData?: string | object): Promise<{
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: any;
}> {
  return new Promise((resolve, reject) => {
    const dataStr = bodyData ? (typeof bodyData === 'string' ? bodyData : JSON.stringify(bodyData)) : '';
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: 3000,
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(bodyData ? { 'Content-Length': Buffer.byteLength(dataStr) } : {}),
          ...(options.headers || {}),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          let parsed = raw;
          try {
            parsed = JSON.parse(raw);
          } catch {}
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers,
            body: parsed,
          });
        });
      }
    );

    req.on('error', reject);
    if (dataStr) req.write(dataStr);
    req.end();
  });
}

async function runApiTests() {
  console.log('\n=============================================================');
  console.log('NUSANTARA-SMS — HTTP SECURITY & HARDENING ACCEPTANCE TEST');
  console.log('=============================================================\n');

  // --- PRIORITAS 1: COLLECTOR SECURITY & ACCESS CONTROL ---
  const initialAdminToken = StorageEngine.getAdminToken();
  const initialCollectorToken = StorageEngine.getCollectorAuthToken();

  // Test 1: Public Forwarder Script must NEVER leak active COLLECTOR_TOKEN
  const publicScriptRes = await makeRequest({ method: 'GET', path: '/api/collector/script' });
  const publicScriptText = typeof publicScriptRes.body === 'string' ? publicScriptRes.body : '';
  const noTokenInPublicScript =
    publicScriptRes.statusCode === 200 &&
    !publicScriptText.includes(initialCollectorToken) &&
    publicScriptText.includes('<PASTE_YOUR_COLLECTOR_TOKEN_HERE>');
  record(
    'Public Script Token Leak Prevention',
    'COLLECTOR SECURITY',
    noTokenInPublicScript,
    `Status: ${publicScriptRes.statusCode}; Active token not present; Placeholder found`
  );

  // Test 2: Pre-configured Script Download without Admin Token MUST return 401
  const unauthConfiguredRes = await makeRequest({ method: 'GET', path: '/api/collector/script?configured=true' });
  record(
    'Pre-Configured Script Download Unauthorized Check',
    'COLLECTOR SECURITY',
    unauthConfiguredRes.statusCode === 401,
    `Status: ${unauthConfiguredRes.statusCode} (Access denied without X-Admin-Token)`
  );

  // Test 3: Pre-configured Script Download with valid Admin Token MUST succeed
  const authConfiguredRes = await makeRequest({
    method: 'GET',
    path: '/api/collector/script?configured=true',
    headers: { 'X-Admin-Token': initialAdminToken },
  });
  const configuredText = typeof authConfiguredRes.body === 'string' ? authConfiguredRes.body : '';
  const configuredHasToken =
    authConfiguredRes.statusCode === 200 &&
    configuredText.includes(initialCollectorToken);
  record(
    'Admin-Authorized Pre-Configured Script Download',
    'COLLECTOR SECURITY',
    configuredHasToken,
    `Status: ${authConfiguredRes.statusCode}; Active token injected securely for authenticated admin`
  );

  // Test 4: Token Rotation without Admin Token MUST return 401
  const unauthRotateRes = await makeRequest({
    method: 'POST',
    path: '/api/collector/rotate-token',
    headers: { 'X-Collector-Token': initialCollectorToken }, // Collector token should NOT authorize admin action
  });
  record(
    'Admin Authorization on Token Rotation (Reject Unprivileged)',
    'COLLECTOR SECURITY',
    unauthRotateRes.statusCode === 401,
    `Status: ${unauthRotateRes.statusCode} (Only X-Admin-Token authorized to rotate)`
  );

  // Test 5: Token Rotation with Admin Token MUST succeed and return new secret
  const authRotateRes = await makeRequest({
    method: 'POST',
    path: '/api/collector/rotate-token',
    headers: { 'X-Admin-Token': initialAdminToken },
  });
  const rotateSuccess =
    authRotateRes.statusCode === 200 &&
    typeof authRotateRes.body.newToken === 'string' &&
    authRotateRes.body.newToken.length >= 24;
  const rotatedCollectorToken = authRotateRes.body.newToken;
  record(
    'Admin-Authorized Token Rotation',
    'COLLECTOR SECURITY',
    rotateSuccess,
    `Status: ${authRotateRes.statusCode}; Rotated successfully (new token: ${rotatedCollectorToken?.slice(0, 8)}...)`
  );

  // Test 6: Verify Loopback Authentication Bypass is Eliminated
  // A request without token must fail with 401 even when sent from 127.0.0.1
  const noTokenHeartbeat = await makeRequest(
    {
      method: 'POST',
      path: '/api/collector/heartbeat',
    },
    { version: '1.2.0-collector' }
  );
  record(
    'Elimination of Loopback Authentication Bypass',
    'COLLECTOR SECURITY',
    noTokenHeartbeat.statusCode === 401,
    `Status: ${noTokenHeartbeat.statusCode} (Collector endpoints strictly require authentication)`
  );

  // Test 7: Collector Heartbeat with New Rotated Token Succeeds
  const validHeartbeat = await makeRequest(
    {
      method: 'POST',
      path: '/api/collector/heartbeat',
      headers: { 'X-Collector-Token': rotatedCollectorToken },
    },
    {
      version: '1.2.0-collector',
      collectorIp: '192.168.100.75',
      suricataActive: true,
      wafActive: true,
      apacheActive: true,
    }
  );
  record(
    'Collector Authentication with Rotated Token',
    'COLLECTOR SECURITY',
    validHeartbeat.statusCode === 200,
    `Status: ${validHeartbeat.statusCode} (Heartbeat accepted with valid rotated credentials)`
  );

  // --- PRIORITAS 4: SENSOR STATE & TRANSPARENCY ---
  // Test 8: Health endpoint component breakdown
  const healthRes = await makeRequest({ method: 'GET', path: '/api/health' });
  const hasComponents =
    healthRes.statusCode === 200 &&
    healthRes.body.components?.suricataFeed !== undefined &&
    healthRes.body.components?.dvwaTarget !== undefined &&
    healthRes.body.components?.databaseStorage !== undefined &&
    healthRes.body.components?.wafInspection !== undefined &&
    healthRes.body.components?.sseEventBus !== undefined;
  const storageNameCorrect =
    healthRes.body.components?.databaseStorage?.type === 'Atomic File Persistence (Crash-Resilient JSON Store)';
  record(
    'Component-by-Component Health Transparency',
    'TRANSPARENCY',
    hasComponents && storageNameCorrect,
    `Suricata: ${healthRes.body.components?.suricataFeed?.status}; Storage: ${healthRes.body.components?.databaseStorage?.type}`
  );

  // Test 9: Zero Dummy Data Baseline Verification
  await makeRequest({ method: 'POST', path: '/api/pipeline/reset' });
  const summaryRes = await makeRequest({ method: 'GET', path: '/api/dashboard/summary' });
  const isPristine =
    summaryRes.statusCode === 200 &&
    summaryRes.body.totalDetectedAttacks === 0 &&
    summaryRes.body.totalEvents === 0;
  record(
    'Zero Dummy Data Baseline Verification',
    'ZERO DUMMY DATA',
    isPristine,
    `Events: ${summaryRes.body.totalEvents}, Detected Attacks: ${summaryRes.body.totalDetectedAttacks}`
  );

  console.log('\n=============================================================');
  const total = results.length;
  const passedCount = results.filter((r) => r.passed).length;
  console.log(`Total API Tests: ${total} | Passed: ${passedCount} | Failed: ${total - passedCount}`);
  console.log('=============================================================\n');

  if (passedCount === total) {
    console.log('\x1b[32m✔ ALL API HARDENING & ACCEPTANCE CHECKS PASSED!\x1b[0m\n');
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runApiTests().catch((err) => {
  console.error('Fatal API test error:', err);
  process.exit(1);
});
