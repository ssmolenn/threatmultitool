function renderEmailResults(data) {
  const container = document.createElement("div");

  // 1. Summary card
  container.appendChild(makeCard("✉", "Header Summary", null, body => {
    const s = data.summary;
    body.appendChild(makeKV([
      ["From", s.from],
      ["To", s.to],
      ["Reply-To", s.reply_to],
      ["Subject", s.subject],
      ["Date", s.date],
      ["Message-ID", s.message_id],
      ["X-Mailer", s.x_mailer],
      ["X-Originating-IP", s.x_originating_ip],
    ]));
  }, true));

  // 2. Phishing score card
  const ph = data.phishing;
  const phLevel = ph.level || "LOW";
  container.appendChild(makeCard("⚠", "Phishing Risk Assessment", makeBadge(phLevel, phLevel), body => {
    const scoreDiv = document.createElement("div");
    scoreDiv.className = "score-display";
    const num = document.createElement("div");
    num.className = `score-number ${phLevel.toLowerCase()}`;
    num.textContent = ph.score;
    const info = document.createElement("div");
    const infoLabel = document.createElement("div");
    infoLabel.style.cssText = "color:var(--text-muted);font-size:11px;text-transform:uppercase;margin-bottom:4px";
    infoLabel.textContent = "Risk Score";
    const infoCount = document.createElement("div");
    infoCount.style.cssText = "color:var(--text);font-size:12px";
    infoCount.textContent = ph.indicators.length + " indicator(s) detected";
    info.appendChild(infoLabel);
    info.appendChild(infoCount);
    scoreDiv.appendChild(num);
    scoreDiv.appendChild(info);
    body.appendChild(scoreDiv);

    if (ph.indicators.length > 0) {
      const ul = document.createElement("ul");
      ul.className = "indicators";
      ph.indicators.forEach(ind => {
        const li = document.createElement("li");
        li.className = "indicator-item";
        const bullet = document.createElement("span");
        bullet.className = "indicator-bullet";
        bullet.textContent = "▸";
        li.appendChild(bullet);
        li.appendChild(document.createTextNode(ind));
        ul.appendChild(li);
      });
      body.appendChild(ul);
    }
  }, true));

  // 2b. Lookalike domain card (only if suspicious)
  const lookalike = data.lookalike_domains || {};
  if (Object.keys(lookalike).length > 0) {
    container.appendChild(makeCard("⚠", "Lookalike Domain Detection", makeBadge("SUSPICIOUS DOMAIN", "critical"), body => {
      Object.entries(lookalike).forEach(([field, result]) => {
        (result.findings || []).forEach(finding => {
          const item = document.createElement("div");
          item.style.cssText = "background:rgba(248,81,73,0.08);border:1px solid var(--red);border-radius:4px;padding:10px 12px;margin-bottom:8px;";
          const sev = document.createElement("div");
          sev.style.cssText = "display:flex;align-items:center;gap:8px;margin-bottom:4px;";
          sev.appendChild(makeBadge(finding.severity, finding.severity === "CRITICAL" ? "critical" : "high"));
          const fieldBadge = document.createElement("span");
          fieldBadge.className = "tag tag-blue";
          fieldBadge.textContent = field.replace("_", "-").toUpperCase();
          sev.appendChild(fieldBadge);
          const detail = document.createElement("div");
          detail.style.cssText = "color:var(--text);font-size:12px;margin-top:4px;";
          detail.textContent = finding.detail;
          if (finding.target) {
            const target = document.createElement("div");
            target.style.cssText = "color:var(--text-muted);font-size:11px;margin-top:2px;";
            target.textContent = `Impersonating: ${finding.target}`;
            item.appendChild(sev);
            item.appendChild(detail);
            item.appendChild(target);
          } else {
            item.appendChild(sev);
            item.appendChild(detail);
          }
          body.appendChild(item);
        });
      });
    }, true));
  }

  // 3. Routing hops
  const hops = data.routing_hops || [];
  container.appendChild(makeCard("⤳", `Routing Hops (${hops.length})`, null, body => {
    if (hops.length === 0) {
      body.textContent = "No Received headers found.";
      return;
    }
    const timeline = document.createElement("div");
    timeline.className = "hop-timeline";
    hops.forEach(hop => {
      const item = document.createElement("div");
      item.className = "hop-item";

      const line = document.createElement("div");
      line.className = "hop-line";
      const dot = document.createElement("div");
      dot.className = "hop-dot";
      const connector = document.createElement("div");
      connector.className = "hop-connector";
      line.appendChild(dot);
      line.appendChild(connector);

      const content = document.createElement("div");
      content.className = "hop-content";

      const num = document.createElement("div");
      num.className = "hop-num";
      num.textContent = `HOP ${hop.hop}`;
      content.appendChild(num);

      if (hop.from) {
        const f = document.createElement("div");
        f.className = "hop-field";
        f.innerHTML = `from <span>${escapeText(hop.from)}</span>`;
        content.appendChild(f);
      }
      if (hop.by) {
        const b = document.createElement("div");
        b.className = "hop-field";
        b.innerHTML = `by <span>${escapeText(hop.by)}</span>`;
        content.appendChild(b);
      }
      if (hop.with) {
        const w = document.createElement("div");
        w.className = "hop-field";
        w.innerHTML = `with <span>${escapeText(hop.with)}</span>`;
        content.appendChild(w);
      }
      if (hop.ip) {
        const ip = document.createElement("span");
        ip.className = "hop-ip-badge";
        ip.textContent = hop.ip;
        content.appendChild(ip);

        // Reputation inline
        const rep = (data.ip_reputation || {})[hop.ip];
        if (rep) {
          const score = rep.abuse_score;
          const scoreSpan = document.createElement("span");
          scoreSpan.className = "hop-ip-badge";
          scoreSpan.style.marginLeft = "4px";
          scoreSpan.style.borderColor = score > 50 ? "var(--red)" : score > 10 ? "var(--yellow)" : "var(--green)";
          scoreSpan.style.color = score > 50 ? "var(--red)" : score > 10 ? "var(--yellow)" : "var(--green)";
          scoreSpan.textContent = `Abuse: ${score}%`;
          content.appendChild(scoreSpan);
          if (rep.geo && rep.geo.country) {
            const geo = document.createElement("span");
            geo.className = "hop-ip-badge";
            geo.style.marginLeft = "4px";
            geo.textContent = `${rep.geo.country}${rep.geo.city ? " · " + rep.geo.city : ""}`;
            content.appendChild(geo);
          }
        }
      }
      if (hop.timestamp) {
        const ts = document.createElement("div");
        ts.className = "hop-field";
        ts.style.marginTop = "4px";
        ts.style.color = "var(--text-dim)";
        ts.textContent = hop.timestamp;
        content.appendChild(ts);
      }

      item.appendChild(line);
      item.appendChild(content);
      timeline.appendChild(item);
    });
    body.appendChild(timeline);
  }));

  // 4. IP Reputation
  const ips = data.ip_reputation || {};
  const ipKeys = Object.keys(ips);
  container.appendChild(makeCard("⬡", `IP Reputation (${ipKeys.length})`, null, body => {
    if (ipKeys.length === 0) {
      body.textContent = "No public IPs found in headers.";
      return;
    }
    const cards = document.createElement("div");
    cards.className = "ip-cards";
    ipKeys.forEach(ip => {
      const rep = ips[ip];
      const score = rep.abuse_score ?? null;
      const card = document.createElement("div");
      card.className = "ip-card";

      const hdr = document.createElement("div");
      hdr.className = "ip-header";

      const addr = document.createElement("span");
      addr.className = "ip-address";
      addr.textContent = ip;

      hdr.appendChild(addr);
      if (score !== null) {
        const levelText = score > 50 ? "HIGH RISK" : score > 10 ? "SUSPICIOUS" : "CLEAN";
        const levelClass = score > 50 ? "critical" : score > 10 ? "warn" : "clean";
        hdr.appendChild(makeBadge(`Abuse: ${score}%`, levelClass));
      }
      card.appendChild(hdr);

      const details = document.createElement("div");
      details.className = "ip-details";

      const fields = [
        ["ISP", rep.isp],
        ["Country", rep.country],
        ["Reports", rep.total_reports != null ? rep.total_reports + " reports" : null],
        ["Last reported", rep.last_reported],
        ["City", rep.geo?.city],
        ["Region", rep.geo?.region],
        ["Org", rep.geo?.org],
        ["Hostname", rep.geo?.hostname],
      ];
      fields.forEach(([k, v]) => {
        if (v) {
          const d = document.createElement("div");
          d.className = "ip-detail";
          d.innerHTML = `${k}: <span>${escapeText(String(v))}</span>`;
          details.appendChild(d);
        }
      });

      if (rep.virustotal) {
        const vt = rep.virustotal;
        const d = document.createElement("div");
        d.className = "ip-detail";
        d.innerHTML = `VT malicious: <span style="color:${vt.malicious > 0 ? "var(--red)" : "var(--green)"}">${vt.malicious}</span>`;
        details.appendChild(d);
      }

      card.appendChild(details);
      cards.appendChild(card);
    });
    body.appendChild(cards);
  }));

  // 5. Authentication
  const auth = data.authentication || {};
  const dns = auth.dns || {};
  container.appendChild(makeCard("🔐", "Authentication (SPF / DKIM / DMARC)", null, body => {
    const grid = document.createElement("div");
    grid.className = "auth-grid";

    // SPF
    const spf = dns.spf || {};
    const spfCard = _authCard("SPF", spf.found ? spf.policy : "not found",
      spf.found && !["hardfail","softfail"].includes(spf.policy) ? "low" : spf.found ? "medium" : "high",
      spf.record || "No SPF record found");
    grid.appendChild(spfCard);

    // DKIM
    const dkim = dns.dkim || {};
    const dkimCard = _authCard("DKIM", dkim.found ? `found (${dkim.selector})` : "not found",
      dkim.found ? "low" : "high",
      dkim.record || "No DKIM record found");
    grid.appendChild(dkimCard);

    // DMARC
    const dmarc = dns.dmarc || {};
    const dmarcCard = _authCard("DMARC", dmarc.found ? `p=${dmarc.policy}` : "not found",
      dmarc.found && dmarc.policy !== "none" ? "low" : dmarc.found ? "medium" : "high",
      dmarc.record || "No DMARC record found");
    grid.appendChild(dmarcCard);

    // Raw header results
    const rawSpf = auth.headers?.spf_header;
    if (rawSpf) {
      const rawCard = _authCard("SPF Result (header)", rawSpf.substring(0, 40),
        rawSpf.toLowerCase().includes("pass") ? "low" : "medium",
        rawSpf);
      grid.appendChild(rawCard);
    }

    body.appendChild(grid);

    if (dns.domain) {
      const dm = document.createElement("div");
      dm.style.marginTop = "12px";
      dm.style.color = "var(--text-muted)";
      dm.style.fontSize = "11px";
      dm.textContent = `Domain analyzed: ${dns.domain}`;
      if (dns.mx && dns.mx.length > 0) {
        dm.textContent += ` · MX: ${dns.mx.join(", ")}`;
      }
      body.appendChild(dm);
    }
  }));

  // 6. URLs
  const urls = data.urls || [];
  const urlHasMalicious = urls.some(u => u.urlhaus && u.urlhaus.found);
  const urlBadge = urlHasMalicious ? makeBadge("MALICIOUS URL", "critical") : null;
  container.appendChild(makeCard("⬡", `URLs Found (${urls.length})`, urlBadge, body => {
    if (urls.length === 0) {
      body.textContent = "No URLs extracted from email body.";
      return;
    }
    const rows = urls.map(entry => {
      const url = entry.url || entry;
      const urlStr = typeof url === "string" ? url : url;
      const a = document.createElement("a");
      a.href = "#";
      a.textContent = urlStr.length > 70 ? urlStr.substring(0, 70) + "…" : urlStr;
      a.title = urlStr;
      a.style.color = "var(--accent)";
      a.addEventListener("click", e => { e.preventDefault(); copyToClipboard(urlStr, a); });

      const uh = entry.urlhaus;
      let statusEl;
      if (uh && uh.found) {
        statusEl = makeBadge(`MALICIOUS · ${uh.threat || uh.url_status}`, "critical");
      } else if (uh && !uh.found) {
        statusEl = makeBadge("clean", "clean");
      } else if (uh === null) {
        statusEl = document.createElement("span");
        statusEl.style.color = "var(--text-dim)";
        statusEl.textContent = "not checked";
      } else {
        statusEl = document.createElement("span");
        statusEl.style.color = "var(--text-dim)";
        statusEl.textContent = "—";
      }
      return [a, statusEl];
    });
    body.appendChild(makeTable(["URL (click to copy)", "URLhaus"], rows));
  }));

  // 7. Attachments
  const attachments = data.attachments || [];
  container.appendChild(makeCard("📎", `Attachments (${attachments.length})`, null, body => {
    if (attachments.length === 0) {
      body.textContent = "No attachments found.";
      return;
    }
    const rows = attachments.map(att => {
      const flags = att.flags || [];
      const flagsEl = document.createElement("div");
      flagsEl.className = "tag-list";
      if (flags.length === 0) {
        flagsEl.appendChild(Object.assign(document.createElement("span"), { className: "tag tag-green", textContent: "clean" }));
      } else {
        flags.forEach(f => {
          flagsEl.appendChild(Object.assign(document.createElement("span"), { className: "tag tag-red", textContent: f }));
        });
      }
      const hashDiv = document.createElement("div");
      hashDiv.style.fontSize = "10px";
      hashDiv.style.color = "var(--text-muted)";
      hashDiv.textContent = att.sha256 ? att.sha256.substring(0, 16) + "…" : "";
      hashDiv.title = att.sha256 || "";
      return [att.filename, att.content_type, formatBytes(att.size_bytes), hashDiv, flagsEl];
    });
    body.appendChild(makeTable(["Filename", "Type", "Size", "SHA-256 (partial)", "Flags"], rows));
  }));

  // 8. Raw headers
  container.appendChild(makeCard("⬡", "Raw Headers", null, body => {
    const pre = document.createElement("pre");
    pre.textContent = data.raw_headers || "";
    body.appendChild(pre);
  }));

  return container;
}

function _authCard(label, value, level, detail) {
  const card = document.createElement("div");
  card.className = "auth-card";
  const lbl = document.createElement("div");
  lbl.className = "auth-label";
  lbl.textContent = label;
  const valDiv = document.createElement("div");
  valDiv.style.display = "flex";
  valDiv.style.alignItems = "center";
  valDiv.style.gap = "8px";
  valDiv.style.marginBottom = "6px";
  const badge = makeBadge(value, level);
  valDiv.appendChild(badge);
  const det = document.createElement("div");
  det.className = "auth-value";
  det.style.fontSize = "10px";
  det.style.color = "var(--text-dim)";
  det.textContent = detail && detail.length > 100 ? detail.substring(0, 100) + "…" : (detail || "");
  det.title = detail || "";
  card.appendChild(lbl);
  card.appendChild(valDiv);
  card.appendChild(det);
  return card;
}

function escapeText(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}
