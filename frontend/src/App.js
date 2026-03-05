// src/App.js
import React, { useState, useEffect, useRef } from 'react';
import './App.css';


// Use env-configured API URL with a sensible default
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
const LOGIN_ACCENTS = [
  { primary: '#0ea5e9', secondary: '#22d3ee', glow: 'rgba(14,165,233,0.45)' },
  { primary: '#a855f7', secondary: '#ec4899', glow: 'rgba(232,121,249,0.45)' },
  { primary: '#22c55e', secondary: '#84cc16', glow: 'rgba(74,222,128,0.4)' },
  { primary: '#f97316', secondary: '#facc15', glow: 'rgba(251,191,36,0.4)' },
];

function App() {
  // Single URL scan
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // File upload (batch) scan
  const [file, setFile] = useState(null);
  const [batchResult, setBatchResult] = useState(null);
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchPage, setBatchPage] = useState(0);
  const BATCH_PAGE_SIZE = 50;

  // Dashboard: recent results history (per session)
  const [history, setHistory] = useState([]);
  const [totals, setTotals] = useState({ total: 0, safe: 0, malicious: 0, suspicious: 0, errors: 0 });

  // Canvas ref for animated background
  const canvasRef = useRef(null);
  const lastMouseMoveRef = useRef(0);

  const [riskLoading, setRiskLoading] = useState(false);
  const [loginAccentIndex, setLoginAccentIndex] = useState(0);
  const [loginOpen, setLoginOpen] = useState(true);


  const addToHistory = (entries) => {
    if (!entries || entries.length === 0) return;
    const ts = Date.now();
    const normalized = entries.map(e => ({ ts, ...e }));
    const limited = normalized.slice(0, 200);
    setHistory(prev => {
      const next = [...limited, ...prev];
      return next.slice(0, 200);
    });
    setTotals(prev => {
      const next = { ...prev };
      for (const entry of entries) {
        const status = (entry.status || '').toLowerCase();
        next.total += 1;
        if (status === 'safe') next.safe += 1;
        else if (status === 'malicious') next.malicious += 1;
        else if (status === 'suspicious') next.suspicious += 1;
        else next.errors += 1;
      }
      return next;
    });
  };

  const statusMeta = (status = '') => {
    const normalized = status.toLowerCase();
    const base = {
      icon: 'ℹ️',
      tone: 'status-suspicious',
      headline: "Scan completed",
      subtitle: "We'll keep monitoring this link.",
      gradient: ['#38bdf8', '#6366f1'],
    };
    if (normalized === 'safe') {
      return {
        icon: '✅',
        tone: 'status-safe',
        headline: "You're safe",
        subtitle: 'No malicious indicators detected.',
        gradient: ['#22c55e', '#34d399'],
      };
    }
    if (normalized === 'malicious') {
      return {
        icon: '⚠️',
        tone: 'status-malicious',
        headline: 'Threat detected',
        subtitle: 'This URL looks dangerous. Avoid interacting with it.',
        gradient: ['#f97316', '#ef4444'],
      };
    }
    if (normalized === 'suspicious') {
      return {
        icon: '⚠️',
        tone: 'status-suspicious',
        headline: 'Suspicious behavior',
        subtitle: 'Treat with caution and verify the sender.',
        gradient: ['#facc15', '#f97316'],
      };
    }
    if (normalized === 'error') {
      return {
        icon: '❌',
        tone: 'status-error',
        headline: 'Scan failed',
        subtitle: 'Please try again or check the backend logs.',
        gradient: ['#a855f7', '#6366f1'],
      };
    }
    return base;
  };

  const handleScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    setRiskLoading(false);

    try {
      const res = await fetch(`${API_URL}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      });
      const data = await res.json();
      setResult(data);
      addToHistory([{ url: url.trim(), ...data }]);
    } catch (err) {
      setResult({ error: 'Failed to connect. Is backend running?', status: 'Error' });
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (e) => {
    setFile(e.target.files?.[0] || null);
    setBatchResult(null);
  };

  const handleFileScan = async () => {
    if (!file) return;
    setBatchLoading(true);
    setBatchResult(null);
    setBatchPage(0);

    try {
      const form = new FormData();
      form.append('file', file);

      const res = await fetch(`${API_URL}/check-file`, { method: 'POST', body: form });
      const data = await res.json();
      setBatchResult(data);
      setBatchPage(0);
      if (Array.isArray(data?.results)) {
        const entries = data.results.map(r => ({ url: r.url, status: r.status, threat_type: r.threat_type, confidence: r.confidence, source: r.source, provided_type: r.provided_type }));
        addToHistory(entries);
      }
    } catch (err) {
      setBatchResult({ error: 'Failed to connect. Is backend running?' });
    } finally {
      setBatchLoading(false);
    }
  };

  // Update CSS variables for radial background glow (throttled)
  useEffect(() => {
    const handleMouseMove = (e) => {
      const now = Date.now();
      if (now - lastMouseMoveRef.current < 30) return;
      lastMouseMoveRef.current = now;
      
      const x = e.clientX / window.innerWidth;
      const y = e.clientY / window.innerHeight;
      document.documentElement.style.setProperty('--mouse-x', String(x));
      document.documentElement.style.setProperty('--mouse-y', String(y));
    };
    window.addEventListener('mousemove', handleMouseMove);
    document.documentElement.style.setProperty('--mouse-x', '0.5');
    document.documentElement.style.setProperty('--mouse-y', '0.5');
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  // Canvas particle network (optimized for performance)
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const DPR = Math.min(window.devicePixelRatio || 1, 1.5);
    const state = {
      w: 0,
      h: 0,
      mouseX: window.innerWidth / 2,
      mouseY: window.innerHeight / 2,
      particles: [],
    };

    const resize = () => {
      state.w = window.innerWidth;
      state.h = window.innerHeight;
      canvas.width = Math.floor(state.w * DPR);
      canvas.height = Math.floor(state.h * DPR);
      canvas.style.width = state.w + 'px';
      canvas.style.height = state.h + 'px';
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);

      const count = Math.max(40, Math.min(60, Math.floor((state.w * state.h) / 40000)));
      state.particles = new Array(count).fill(0).map(() => ({
        x: Math.random() * state.w,
        y: Math.random() * state.h,
        vx: (Math.random() * 2 - 1) * 0.3,
        vy: (Math.random() * 2 - 1) * 0.3,
        r: 0.7 + Math.random() * 0.8,
      }));
    };

    const onMove = (e) => {
      state.mouseX = e.clientX;
      state.mouseY = e.clientY;
    };

    window.addEventListener('resize', resize);
    window.addEventListener('mousemove', onMove);
    resize();

    const LINK_DIST = 100;
    const LINK_DIST_SQ = LINK_DIST * LINK_DIST;
    const MOUSE_R = 140;
    const MOUSE_R_SQ = MOUSE_R * MOUSE_R;
    const MAX_SPEED = 0.6;
    const MAX_SPEED_SQ = MAX_SPEED * MAX_SPEED;

    let rafId;
    let frameCount = 0;
    const step = () => {
      const { w, h, mouseX, mouseY, particles } = state;

      ctx.clearRect(0, 0, w, h);

      for (let p of particles) {
        const dx = p.x - mouseX;
        const dy = p.y - mouseY;
        const d2 = dx * dx + dy * dy;
        if (d2 < MOUSE_R_SQ && d2 > 0.0001) {
          const d = Math.sqrt(d2);
          const force = (1 - d / MOUSE_R) * 0.5;
          p.vx += (dx / d) * force;
          p.vy += (dy / d) * force;
        }

        p.vx += (Math.random() - 0.5) * 0.008;
        p.vy += (Math.random() - 0.5) * 0.008;

        const sp2 = p.vx * p.vx + p.vy * p.vy;
        if (sp2 > MAX_SPEED_SQ) {
          const sp = Math.sqrt(sp2);
          p.vx = (p.vx / sp) * MAX_SPEED;
          p.vy = (p.vy / sp) * MAX_SPEED;
        }

        p.x += p.vx;
        p.y += p.vy;

        if (p.x <= 0 || p.x >= w) p.vx *= -1;
        if (p.y <= 0 || p.y >= h) p.vy *= -1;

        ctx.beginPath();
        ctx.fillStyle = 'rgba(14, 165, 233, 0.7)';
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }

      frameCount++;
      if (frameCount % 2 === 0) {
        ctx.lineWidth = 0.7;
        for (let i = 0; i < particles.length; i++) {
          for (let j = i + 1; j < Math.min(i + 8, particles.length); j++) {
            const a = particles[i];
            const b = particles[j];
            const dx = a.x - b.x;
            const dy = a.y - b.y;
            const d2 = dx * dx + dy * dy;
            if (d2 < LINK_DIST_SQ) {
              const dist = Math.sqrt(d2);
              const alpha = (1 - dist / LINK_DIST) * 0.5;
              ctx.strokeStyle = `rgba(6, 182, 212, ${alpha})`;
              ctx.beginPath();
              ctx.moveTo(a.x, a.y);
              ctx.lineTo(b.x, b.y);
              ctx.stroke();
            }
          }
        }
      }

      rafId = requestAnimationFrame(step);
    };

    step();

    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', onMove);
    };
  }, []);

  // Rotate login accent colors
  useEffect(() => {
    if (LOGIN_ACCENTS.length <= 1) return undefined;
    const id = window.setInterval(() => {
      setLoginAccentIndex(prev => (prev + 1) % LOGIN_ACCENTS.length);
    }, 6500);
    return () => window.clearInterval(id);
  }, []);

  const fetchAdvancedRisk = async () => {
    if (!result?.url || riskLoading) return;
    setRiskLoading(true);
    try {
      const res = await fetch(`${API_URL}/ai-risk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: result.url }),
      });
      const data = await res.json();
      setResult(prev => ({ ...(prev || {}), ai_risk: data }));
    } catch (err) {
      console.error(err);
    } finally {
      setRiskLoading(false);
    }
  };

  // Derived dashboard summary
  const summary = totals;
  const batchHasProvidedType = Array.isArray(batchResult?.results) && batchResult.results.some(r => r?.provided_type);
  const historyHasProvidedType = history.some(h => h?.provided_type);
  const selectedStatusMeta = statusMeta(result?.status);
  const confidenceValue = typeof result?.confidence === 'number' ? Math.max(0, Math.min(1, result.confidence)) : null;
  const confidencePercent = confidenceValue !== null ? (confidenceValue * 100).toFixed(0) : null;
  const confidenceWidth = confidenceValue !== null ? `${confidenceValue * 100}%` : '0%';
  const confidenceGradient = `linear-gradient(90deg, ${selectedStatusMeta.gradient[0]}, ${selectedStatusMeta.gradient[1]})`;
  const detailItems = [
    { label: 'Threat', value: result?.threat_type || 'Unknown' },
    { label: 'Source', value: result?.source || 'N/A' },
    { label: 'Protocol', value: result?.url?.startsWith('https') ? 'HTTPS' : 'HTTP' },
    { label: 'Length', value: result?.details?.url_length ?? '—' },
  ];
  const fileLabel = file ? file.name : 'Choose CSV or TXT file';
  const loginPalette = LOGIN_ACCENTS[loginAccentIndex % LOGIN_ACCENTS.length];
  const loginStyles = {
    '--login-accent-primary': loginPalette.primary,
    '--login-accent-secondary': loginPalette.secondary,
    '--login-accent-glow': loginPalette.glow,
  };

  return (
    <div className="App">
      {/* Animated Background */}
      <div className="background">
        <canvas ref={canvasRef} id="bg-canvas" className="bg-canvas" />
      </div>

      {/* Top Navigation */}
      <header className="nav">
        <div className="nav-inner">
          <div className="brand">
            <img className="brand-logo" src="/safesurf-logo.png" alt="Safe Surf" onError={(e) => (e.currentTarget.style.display = 'none')} />
            <span>Safe Surf</span>
          </div>
          <nav className="nav-links">
            <a href="#home">Home</a>
            <a href="#how">How it works</a>
            <a href="#file">File upload</a>
            <a href="#dashboard">Dashboard</a>
            <a href="#about">About</a>
            <a href="#login">Login</a>
          </nav>
          <div className="nav-cta">
            <button className="btn-primary" onClick={() => document.getElementById('home')?.scrollIntoView({behavior:'smooth'})}>Try now</button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section id="home" className="hero">
        <div className="hero-content">
          <h1>Detect Malicious Links Instantly</h1>
          <p>AI-powered phishing, malware, and scam detection. Paste a URL and get a clear, actionable verdict.</p>

          <div className="search-wrap">
            <div className="input-with-prefix">
              <span className="prefix">http</span>
              <input
                type="text"
                placeholder="https://example.com/login"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              />
            </div>
            <button className="btn-primary" onClick={handleScan} disabled={loading}>
              {loading ? 'Scanning…' : 'Scan URL'}
            </button>
          </div>

          <div className="trust-chips">
            <span>Fast</span>
            <span>Privacy‑first</span>
            <span>On‑device scoring</span>
          </div>
        </div>

        <div className="hero-illust" aria-hidden>
          <img src="/safesurf-logo.png" alt="Safe Surf" className="hero-logo" onError={(e)=> (e.currentTarget.style.display='none')} />
        </div>
      </section>

      {/* Result Card */}
      {result && (
        <section className={`result-wrapper ${selectedStatusMeta.tone}`}>
          <div className="result-card-inner">
            <div className="result-headline">
              <div className="alert-icon" aria-hidden>
                {selectedStatusMeta.icon}
              </div>
              <div>
                <p className="result-eyebrow">Verdict · {(result.status || 'Unknown').toUpperCase()}</p>
                <h2>{selectedStatusMeta.headline}</h2>
                <p className="result-subtitle">{selectedStatusMeta.subtitle}</p>
              </div>
            </div>

            {result.error && (
              <p className="result-error"><strong>Error:</strong> {result.error}</p>
            )}

            {!result.error && (
              <>
                <div className="confidence-block">
                  <div className="confidence-text">
                    <span>Confidence</span>
                    <strong>{confidencePercent ? `${confidencePercent}%` : '—'}</strong>
                  </div>
                  <div className="confidence-meter">
                    <div className="bar" style={{ width: confidenceWidth, background: confidenceGradient }} />
                  </div>
                </div>

                <div className="result-details-grid">
                  {detailItems.map((item) => (
                    <div className="detail-pill" key={item.label}>
                      <span className="label">{item.label}</span>
                      <span className="value">{item.value}</span>
                    </div>
                  ))}
                </div>

                <div className="result-url-block">
                  <span className="label">Scanned URL</span>
                  <p className="url-text">{result.url || url}</p>
                </div>
              </>
            )}

            <div className="result-footer">
              <div className="result-source">
                <span className="label">Source</span>
                <span className="value">{result.source || 'Local ML Model'}</span>
              </div>
              <div className="result-actions">
                <button className="btn-outline" onClick={() => setResult(null)}>Clear</button>
                {!result.error && (
                  <button className="btn-primary" onClick={fetchAdvancedRisk} disabled={riskLoading}>
                    {riskLoading ? 'Loading AI Risk…' : 'Advanced AI Risk'}
                  </button>
                )}
              </div>
            </div>

            {result.ai_risk && (
              <div className="ai-risk-block">
                <div className="ai-risk-row">
                  <span>Final risk</span>
                  <strong>
                    {typeof result.ai_risk.final_risk === 'number'
                      ? `${(result.ai_risk.final_risk * 100).toFixed(1)}%`
                      : '—'}
                  </strong>
                </div>
                <pre>{JSON.stringify(result.ai_risk, null, 2)}</pre>
              </div>
            )}
          </div>
        </section>
      )}

      {/* File Upload Section */}
      <section id="file" className="batch">
        <h2>Upload a file of URLs</h2>
        <p>CSV with a column named "url" (or first column) or TXT with one URL per line.</p>
        <div className="batch-controls">
          <label className="upload-field">
            <input type="file" accept=".csv,.txt" onChange={handleFileChange} />
            <span>{fileLabel}</span>
          </label>
          <button className="btn-secondary" onClick={handleFileScan} disabled={batchLoading || !file}>
            {batchLoading ? 'Scanning…' : 'Scan File'}
          </button>
        </div>

        {batchResult && (
          <div className="result-card" style={{ marginTop: 12 }}>
            {batchResult.error ? (
              <p style={{ color: '#ff6b6b' }}><strong>Error:</strong> {batchResult.error}</p>
            ) : (
              <>
                <div className="batch-summary-header">
                  <div>
                    <h3>Summary{batchResult.filename ? `: ${batchResult.filename}` : ''}</h3>
                    <span className="summary-subtitle">{batchResult.summary?.total || 0} URLs processed</span>
                  </div>
                </div>
                <div className="batch-summary-grid">
                  <div className="summary-card">
                    <span className="label">Total</span>
                    <span className="value">{batchResult.summary?.total}</span>
                  </div>
                  <div className="summary-card safe">
                    <span className="label">Safe</span>
                    <span className="value">{batchResult.summary?.safe}</span>
                  </div>
                  <div className="summary-card malicious">
                    <span className="label">Malicious</span>
                    <span className="value">{batchResult.summary?.malicious}</span>
                  </div>
                  <div className="summary-card suspicious">
                    <span className="label">Suspicious</span>
                    <span className="value">{batchResult.summary?.suspicious}</span>
                  </div>
                  <div className="summary-card errors">
                    <span className="label">Errors</span>
                    <span className="value">{batchResult.summary?.errors}</span>
                  </div>
                </div>

                {Array.isArray(batchResult.results) && batchResult.results.length > 0 && (
                  <>
                    <div className="batch-table-wrap">
                      <table className="table batch-table">
                        <thead>
                          <tr>
                            <th>URL</th>
                            {batchHasProvidedType && <th>Provided</th>}
                            <th>Status</th>
                            <th>Threat</th>
                            <th>Confidence</th>
                            <th>Source</th>
                          </tr>
                        </thead>
                        <tbody>
                          {batchResult.results?.slice(batchPage * BATCH_PAGE_SIZE, (batchPage + 1) * BATCH_PAGE_SIZE).map((r, idx) => (
                            <tr key={idx}>
                              <td className="url-cell">{r.url}</td>
                              {batchHasProvidedType && <td>{r.provided_type || '-'}</td>}
                              <td className={`status-pill ${r.status?.toLowerCase()}`}>{r.status}</td>
                              <td>{r.threat_type}</td>
                              <td>{typeof r.confidence === 'number' ? `${(r.confidence * 100).toFixed(1)}%` : '-'}</td>
                              <td>{r.source}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div style={{ marginTop: 16, display: 'flex', gap: 8, justifyContent: 'center', alignItems: 'center' }}>
                      <button className="btn-secondary" onClick={() => setBatchPage(Math.max(0, batchPage - 1))} disabled={batchPage === 0}>← Previous</button>
                      <span style={{ color: '#cbd5e1', fontSize: 14 }}>Page {batchPage + 1} of {Math.ceil((batchResult.results?.length || 0) / BATCH_PAGE_SIZE)}</span>
                      <button className="btn-secondary" onClick={() => setBatchPage(batchPage + 1)} disabled={(batchPage + 1) * BATCH_PAGE_SIZE >= (batchResult.results?.length || 0)}>Next →</button>
                    </div>
                  </>
                )}
              </>
            )}
          </div>
        )}
      </section>

      {/* How it works */}
      <section id="how" className="features">
        <div className="features-header">
          <h2>How Safe Surf works</h2>
          <p>Every link flows through a multi‑layer pipeline so you get verdicts that are both fast and trustworthy.</p>
        </div>
        <div className="feature-grid">
          <div className="feature-card">
            <div className="step-badge">01</div>
            <div className="step-icon step-parse" aria-hidden>🔎</div>
            <h3>URL is decoded</h3>
            <p>We normalize and parse the URL, extracting structure like hostname, path, query, protocol and TLD.</p>
            <ul>
              <li>Length, digits, symbols</li>
              <li>Subdomain depth & homograph hints</li>
              <li>Presence of IPs or shorteners</li>
            </ul>
          </div>
          <div className="feature-card">
            <div className="step-badge">02</div>
            <div className="step-icon step-reputation" aria-hidden>🛡️</div>
            <h3>Reputation checks</h3>
            <p>We query Google Safe Browsing and other signals to instantly block known phishing, malware and fraud.</p>
            <ul>
              <li>Threat intelligence feed</li>
              <li>Malware & phishing categories</li>
              <li>Safe vs. known‑bad decisions</li>
            </ul>
          </div>
          <div className="feature-card">
            <div className="step-badge">03</div>
            <div className="step-icon step-ml" aria-hidden>🤖</div>
            <h3>ML risk scoring</h3>
            <p>Our local model uses 17 engineered features to score how risky the URL looks, even if it is brand new.</p>
            <ul>
              <li>Lexical and hostname patterns</li>
              <li>Training on malicious datasets</li>
              <li>Safe / Suspicious / Malicious output</li>
            </ul>
          </div>
          <div className="feature-card">
            <div className="step-badge">04</div>
            <div className="step-icon step-verdict" aria-hidden>✅</div>
            <h3>Human‑readable verdict</h3>
            <p>You see a clear verdict, confidence bar, and threat type so analysts can act quickly with full context.</p>
            <ul>
              <li>Color‑coded verdict card</li>
              <li>Per‑URL evidence and source</li>
              <li>Bulk dashboards for teams</li>
            </ul>
          </div>
        </div>
      </section>

      {/* Dashboard */}
      <section id="dashboard" className="dashboard">
        <h2>Dashboard</h2>
        <div className="stats">
          <div className="stat-card"><span className="label">Total</span><span className="value total">{summary.total}</span></div>
          <div className="stat-card"><span className="label">Safe</span><span className="value safe">{summary.safe}</span></div>
          <div className="stat-card"><span className="label">Suspicious</span><span className="value suspicious">{summary.suspicious}</span></div>
          <div className="stat-card"><span className="label">Malicious</span><span className="value malicious">{summary.malicious}</span></div>
          <div className="stat-card"><span className="label">Errors</span><span className="value error">{summary.errors}</span></div>
        </div>

        <div className="result-card" style={{ marginTop: 12 }}>
          <h3 style={{textAlign:'left', marginBottom: 8}}>Recent scans</h3>
          <div style={{ maxHeight: 320, overflowY: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>URL</th>
                  {historyHasProvidedType && <th>Provided</th>}
                  <th>Status</th>
                  <th>Threat</th>
                  <th>Confidence</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {history.slice(0, 20).map((h, i) => (
                  <tr key={i}>
                    <td>{new Date(h.ts).toLocaleTimeString()}</td>
                    <td className="truncate">{h.url}</td>
                    {historyHasProvidedType && <td>{h.provided_type || '-'}</td>}
                    <td>{h.status}</td>
                    <td>{h.threat_type}</td>
                    <td>{typeof h.confidence === 'number' ? `${(h.confidence * 100).toFixed(1)}%` : '-'}</td>
                    <td>{h.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* About */}
      <section id="about" className="about">
        <div className="about-inner">
          <div className="about-copy">
            <h2>Built for safe browsing</h2>
            <p>Safe Surf combines cloud‑grade threat intelligence with a lightweight on‑prem model so you can evaluate links without shipping raw traffic to third‑party services.</p>
            <p>Paste a single URL, drag‑and‑drop a CSV of thousands, and get a clean view of what is safe, suspicious, or malicious in seconds.</p>

            <div className="about-pill-row">
              <span className="about-pill">No credentials stored</span>
              <span className="about-pill">Runs on your infra</span>
              <span className="about-pill">Built with Flask + React</span>
            </div>

            <div className="about-metrics">
              <div className="metric">
                <span className="metric-value">17+</span>
                <span className="metric-label">URL features scored</span>
              </div>
              <div className="metric">
                <span className="metric-value">3</span>
                <span className="metric-label">Verdict levels</span>
              </div>
              <div className="metric">
                <span className="metric-value">5000</span>
                <span className="metric-label">URLs per file upload</span>
              </div>
            </div>
          </div>
          <div className="about-grid">
            <div className="about-card">
              <h3>Dual engine</h3>
              <p>We cross‑check every URL with Google Safe Browsing and a local ML classifier to catch both known and brand‑new attacks.</p>
            </div>
            <div className="about-card">
              <h3>Privacy first</h3>
              <p>URLs are evaluated inside your environment; no external logging of your scans, tokens, or dashboards.</p>
            </div>
            <div className="about-card">
              <h3>Analyst friendly</h3>
              <p>Compact dashboards, confidence meters, and threat types make it easy to explain decisions to your team.</p>
            </div>
          </div>
        </div>
      </section>
      {/* Login Section */}
      <section
        id="login"
        className={`login ${loginOpen ? 'open' : 'closed'}`}
        style={loginStyles}
      >
        <div className="login-inner">
          <div className="login-lamp-wrap">
            <div className="login-string" />
            <div className="login-lamp" />
            <div className="login-light" />
          </div>

          <button
            className="login-handle"
            onClick={() => setLoginOpen(prev => !prev)}
            aria-expanded={loginOpen}
          >
            <span className="handle-glow" />
            <span className="handle-icon">{loginOpen ? '⟰' : '⟱'}</span>
            <span>{loginOpen ? 'Push up to hide' : 'Pull down to login'}</span>
          </button>

          <div className={`login-panel ${loginOpen ? 'show' : ''}`}>
            <div className="login-box">
              <h2>Welcome Back</h2>
              <p>Please login to continue to your Safe Surf dashboard.</p>

              <form
                className="login-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  alert('Login successful! (demo)');
                }}
              >
                <div className="login-input">
                  <input type="text" required />
                  <label>Username</label>
                </div>
                <div className="login-input">
                  <input type="password" required />
                  <label>Password</label>
                </div>

                <button type="submit" className="btn-primary">Login</button>
              </form>
            </div>
          </div>
        </div>
      </section>



      <footer className="footer">
        <div className="footer-inner">
          <span>Secure every click · Safe Surf</span>
          <span>Stay vigilant. Stay private.</span>
        </div>
      </footer>
    </div>
  );
}


export default App;
