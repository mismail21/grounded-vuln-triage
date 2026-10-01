import { useEffect, useState } from "react";

const EXAMPLES = {
  "requirements.txt": "# A Flask app last updated in 2018\nFlask==0.12.2\nJinja2==2.10\nrequests==2.19.1\nPyYAML==5.1\nnumpy>=1.20\n",
  "package.json": JSON.stringify(
    { name: "legacy-frontend", dependencies: { jquery: "3.4.0", lodash: "4.17.4", moment: "2.29.1" } },
    null,
    2
  ),
};

const PRIORITY_HELP = {
  P1: "Fix now",
  P2: "Fix this sprint",
  P3: "Plan a fix",
  P4: "Low",
};

function Claim({ claim, format = (v) => v }) {
  if (!claim || claim.status !== "verified") {
    return (
      <span className="unknown" title={claim ? `${claim.status}: ${claim.reason}` : "missing"}>
        review
      </span>
    );
  }
  let v = claim.value;
  if (Array.isArray(v)) v = v.length ? v.join(", ") : "none";
  else if (typeof v === "boolean") v = v ? "YES" : "no";
  else v = format(v);
  return (
    <a href={claim.source_url} target="_blank" rel="noreferrer" className={claim.value === true ? "kev" : ""}>
      {v}
    </a>
  );
}

function Stat({ label, value, tone }) {
  return (
    <div className={`stat ${tone || ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export default function App() {
  const [filename, setFilename] = useState("requirements.txt");
  const [content, setContent] = useState(EXAMPLES["requirements.txt"]);
  const [mode, setMode] = useState("agent");
  const [agentAvailable, setAgentAvailable] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then((h) => {
        setAgentAvailable(h.agent_available);
        if (!h.agent_available) setMode("baseline");
      })
      .catch(() => {});
  }, []);

  function loadExample(name) {
    setFilename(name);
    setContent(EXAMPLES[name]);
  }

  async function onFile(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    setFilename(f.name);
    setContent(await f.text());
  }

  async function scan() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const r = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename, content, mode }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
      setResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  const c = result?.checked;
  const s = c?.stats;
  const review = c
    ? [
        ...c.omitted.map((o) => ({ kind: "Not triaged by agent", text: `${o.package} ${o.installed_version} · ${o.vuln_id} — ${o.summary}`, url: o.source_urls[0] })),
        ...c.rejected_findings.map((r) => ({ kind: "Rejected claim", text: `${r.package} ${r.vuln_id} — ${r.reason}` })),
        ...c.unresolved_dependencies.map((u) => ({ kind: "Unknown version", text: `${u.dependency} — ${u.note}` })),
        ...c.review_notes.map((n) => ({ kind: "Agent note", text: n })),
        ...c.errors.map((e) => ({ kind: "Data source error", text: e })),
      ]
    : [];

  return (
    <div className="page">
      <header>
        <h1>Grounded Vulnerability Triage</h1>
        <p className="tagline">
          An AI agent that triages your dependencies' known vulnerabilities. <strong>No source, no value:</strong> every
          number links to the record it came from, and anything unsupported is removed or sent for human review.
        </p>
      </header>

      <section className="input card">
        <div className="row">
          <div className="tabs">
            {Object.keys(EXAMPLES).map((n) => (
              <button key={n} className={filename === n ? "tab active" : "tab"} onClick={() => loadExample(n)}>
                {n} example
              </button>
            ))}
            <label className="tab upload">
              Upload file…
              <input type="file" accept=".txt,.json,.in" onChange={onFile} hidden />
            </label>
          </div>
          <span className="filename">{filename}</span>
        </div>
        <textarea value={content} onChange={(e) => setContent(e.target.value)} spellCheck={false} rows={9} />
        <div className="row">
          <div className="mode">
            <label title={agentAvailable ? "" : "No model API key configured on the server"}>
              <input type="radio" checked={mode === "agent"} disabled={!agentAvailable} onChange={() => setMode("agent")} />
              AI agent
            </label>
            <label>
              <input type="radio" checked={mode === "baseline"} onChange={() => setMode("baseline")} />
              Baseline (no AI)
            </label>
          </div>
          <button className="primary" onClick={scan} disabled={loading || !content.trim()}>
            {loading ? (mode === "agent" ? "Agent is working… (≈1–2 min)" : "Scanning…") : "Scan dependencies"}
          </button>
        </div>
        {error && <div className="error">{error}</div>}
      </section>

      {c && (
        <>
          <section className="stats">
            <Stat label="findings" value={s.findings_accepted} />
            <Stat label="claims verified" value={`${s.verified}/${s.claims_total}`} tone="good" />
            <Stat label="unsupported claims removed" value={s.unsourced + s.ungrounded + s.mismatch} tone={s.unsourced + s.ungrounded + s.mismatch ? "warn" : "good"} />
            <Stat label="items for human review" value={s.findings_needing_review + review.length} tone={review.length ? "warn" : ""} />
            {result.mode === "agent" && <Stat label={`${result.model} · ${result.turns} turns`} value={`${result.seconds}s`} />}
          </section>

          <section className="card">
            <h2>Prioritized findings</h2>
            {c.findings.length === 0 ? (
              <p className="muted">No triaged findings.</p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Priority</th><th>Package</th><th>Vulnerability</th><th>CVSS</th><th>KEV</th><th>EPSS</th><th>Fixed in</th><th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {c.findings.map((f) => (
                      <tr key={f.package + f.vuln_id}>
                        <td><span className={`badge ${f.priority}`} title={PRIORITY_HELP[f.priority]}>{f.priority}</span></td>
                        <td className="mono">{f.package} {f.installed_version}</td>
                        <td>
                          <div className="mono">{f.vuln_id}</div>
                          <div className="summary"><Claim claim={f.claims.summary} /></div>
                          <div className="rationale">{f.rationale}</div>
                        </td>
                        <td><Claim claim={f.claims.cvss_score} /></td>
                        <td><Claim claim={f.claims.in_kev} /></td>
                        <td><Claim claim={f.claims.epss} format={(v) => v.toFixed(3)} /></td>
                        <td className="mono"><Claim claim={f.claims.fixed_versions} /></td>
                        <td title={f.review_reasons.join("\n")}>
                          {f.status === "verified" ? <span className="ok">✓ verified</span> : <span className="unknown">needs review</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {c.remediations.length > 0 && (
            <section className="card">
              <h2>Fix plan</h2>
              <table>
                <thead><tr><th>Package</th><th>Current</th><th>Upgrade to</th><th>Checked against OSV</th></tr></thead>
                <tbody>
                  {c.remediations.map((r) => (
                    <tr key={r.package}>
                      <td className="mono">{r.package}</td>
                      <td className="mono">{r.current_version}</td>
                      <td className="mono">{r.recommended_version || "—"}</td>
                      <td>
                        {r.status === "verified" ? <span className="ok">✓ clears all known issues</span> : <span className="unknown">{r.reason || r.status}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          {review.length > 0 && (
            <section className="card">
              <h2>Needs human review</h2>
              <ul className="review">
                {review.map((r, i) => (
                  <li key={i}>
                    <span className="pill">{r.kind}</span> {r.url ? <a href={r.url} target="_blank" rel="noreferrer">{r.text}</a> : r.text}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {result.trace?.length > 0 && (
            <details className="card">
              <summary>Agent tool calls ({result.trace.length})</summary>
              <ol className="trace">
                {result.trace.map((t, i) => (
                  <li key={i} className={t.is_error ? "err" : ""}>
                    <code>{t.tool}</code> <span className="muted">{JSON.stringify(t.input).slice(0, 160)}</span>
                  </li>
                ))}
              </ol>
            </details>
          )}
        </>
      )}
      <footer>
        Data: <a href="https://osv.dev">OSV.dev</a> · <a href="https://nvd.nist.gov">NVD</a> ·{" "}
        <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a> ·{" "}
        <a href="https://www.first.org/epss/">FIRST EPSS</a>
      </footer>
    </div>
  );
}
