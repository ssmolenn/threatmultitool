function renderFileResults(data) {
  const container = document.createElement("div");

  // 1. Overview card
  const risk = data.risk_assessment || {};
  const level = risk.level || "LOW";
  container.appendChild(makeCard("⬡", "File Overview", makeBadge(level + " RISK", level), body => {
    const scoreDiv = document.createElement("div");
    scoreDiv.className = "score-display";
    const num = document.createElement("div");
    num.className = `score-number ${level.toLowerCase()}`;
    num.textContent = risk.score || 0;
    const info = document.createElement("div");
    const infoLabel = document.createElement("div");
    infoLabel.style.cssText = "color:var(--text-muted);font-size:11px;text-transform:uppercase;margin-bottom:4px";
    infoLabel.textContent = "Risk Score";
    const infoName = document.createElement("div");
    infoName.style.cssText = "color:var(--text);font-size:12px";
    infoName.textContent = data.filename;
    const infoSize = document.createElement("div");
    infoSize.style.cssText = "color:var(--text-muted);font-size:11px";
    infoSize.textContent = formatBytes(data.file_size_bytes || 0);
    info.appendChild(infoLabel);
    info.appendChild(infoName);
    info.appendChild(infoSize);
    scoreDiv.appendChild(num);
    scoreDiv.appendChild(info);
    body.appendChild(scoreDiv);

    if (risk.indicators && risk.indicators.length > 0) {
      const ul = document.createElement("ul");
      ul.className = "indicators";
      risk.indicators.forEach(ind => {
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

  // 2. Hashes
  container.appendChild(makeCard("⬡", "File Hashes", null, body => {
    const hashes = data.hashes || {};
    const entries = [["MD5", hashes.md5], ["SHA-1", hashes.sha1], ["SHA-256", hashes.sha256]];
    entries.forEach(([algo, val]) => {
      if (!val) return;
      const row = document.createElement("div");
      row.className = "hash-row";
      const algoEl = document.createElement("div");
      algoEl.className = "hash-algo";
      algoEl.textContent = algo;
      const valEl = document.createElement("div");
      valEl.className = "hash-value";
      valEl.textContent = val;
      const copyBtn = document.createElement("button");
      copyBtn.className = "copy-btn";
      copyBtn.textContent = "copy";
      copyBtn.addEventListener("click", () => copyToClipboard(val, copyBtn));
      row.appendChild(algoEl);
      row.appendChild(valEl);
      row.appendChild(copyBtn);
      body.appendChild(row);
    });
  }, true));

  // 3. VirusTotal
  const vt = data.virustotal || {};
  const vtBadge = _vtBadge(vt);
  container.appendChild(makeCard("⬡", "VirusTotal", vtBadge, body => {
    if (vt.error) {
      body.textContent = vt.error === "VirusTotal API key not configured"
        ? "VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to backend/.env"
        : "Error: " + vt.error;
      return;
    }
    if (!vt.found) {
      body.textContent = "Hash not found in VirusTotal database. File may be new or not yet scanned.";
      return;
    }
    body.appendChild(makeKV([
      ["Malicious engines", vt.malicious],
      ["Suspicious engines", vt.suspicious],
      ["Harmless engines", vt.harmless],
      ["Undetected engines", vt.undetected],
      ["File name (VT)", vt.name],
      ["File type (VT)", vt.type],
      ["VT permalink", vt.permalink],
    ]));
  }, true));

  // 4. File type
  const ft = data.file_type || {};
  container.appendChild(makeCard("⬡", "File Type Detection", null, body => {
    const mismatch = ft.extension_match === false;
    if (mismatch) {
      const warn = document.createElement("div");
      warn.style.cssText = "background:rgba(248,81,73,0.1);border:1px solid var(--red);border-radius:4px;padding:8px 12px;margin-bottom:12px;color:var(--red);font-size:12px;";
      warn.textContent = `⚠ Extension mismatch: file claims to be .${ft.declared_extension} but magic bytes say: ${ft.magic}`;
      body.appendChild(warn);
    }
    body.appendChild(makeKV([
      ["Magic type", ft.magic],
      ["MIME type", ft.mime],
      ["Declared extension", ft.declared_extension ? "." + ft.declared_extension : "none"],
      ["Extension match", mismatch ? "NO — mismatch!" : "Yes"],
    ]));
  }));

  // 5. Metadata
  const meta = data.metadata || {};
  if (Object.keys(meta).length > 0) {
    container.appendChild(makeCard("⬡", "File Metadata", null, body => {
      const pairs = Object.entries(meta).map(([k, v]) => {
        if (Array.isArray(v)) return [k, v.join(", ")];
        return [k, String(v)];
      });
      body.appendChild(makeKV(pairs));
    }));
  }

  // 6. YARA
  const yara = data.yara || {};
  const yaraMatches = yara.matches || [];
  const yaraBadge = yaraMatches.length > 0 ? makeBadge(yaraMatches.length + " MATCH" + (yaraMatches.length > 1 ? "ES" : ""), "high") : makeBadge("CLEAN", "clean");
  container.appendChild(makeCard("⬡", "YARA Scan", yaraBadge, body => {
    if (yara.error) {
      body.textContent = "YARA: " + yara.error;
      return;
    }
    if (yaraMatches.length === 0) {
      body.textContent = "No YARA rules matched.";
      return;
    }
    yaraMatches.forEach(match => {
      const card = document.createElement("div");
      card.style.cssText = "background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:10px 12px;margin-bottom:8px;";

      const title = document.createElement("div");
      title.style.cssText = "color:var(--orange);font-weight:700;margin-bottom:6px;";
      title.textContent = match.rule;
      card.appendChild(title);

      if (match.meta && match.meta.description) {
        const desc = document.createElement("div");
        desc.style.cssText = "color:var(--text-muted);font-size:12px;margin-bottom:6px;";
        desc.textContent = match.meta.description;
        card.appendChild(desc);
      }

      if (match.tags && match.tags.length > 0) {
        const tags = document.createElement("div");
        tags.className = "tag-list";
        match.tags.forEach(t => {
          const span = document.createElement("span");
          span.className = "tag tag-orange";
          span.textContent = t;
          tags.appendChild(span);
        });
        card.appendChild(tags);
      }

      body.appendChild(card);
    });
  }));

  // 7. Entropy
  const entropy = data.entropy || {};
  const overall = entropy.overall || {};
  const entLevel = overall.level || "CLEAN";
  const entBadge = makeBadge(`${overall.entropy || 0}`, entLevel === "CRITICAL" || entLevel === "HIGH" ? entLevel : "info");
  container.appendChild(makeCard("⬡", "Entropy Analysis", entBadge, body => {
    const overallDiv = document.createElement("div");
    overallDiv.style.cssText = "margin-bottom:12px;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;";
    const entColor = entLevel === "CRITICAL" ? "var(--red)" : entLevel === "HIGH" ? "var(--orange)" : entLevel === "MEDIUM" ? "var(--yellow)" : "var(--green)";
    const entFlex = document.createElement("div");
    entFlex.style.cssText = "display:flex;align-items:center;gap:12px;";
    const entNum = document.createElement("div");
    entNum.style.cssText = `font-size:28px;font-weight:700;color:${entColor}`;
    entNum.textContent = overall.entropy || 0;
    const entInfo = document.createElement("div");
    const entDesc = document.createElement("div");
    entDesc.style.cssText = "color:var(--text);font-size:12px;font-weight:600;";
    entDesc.textContent = overall.description || "";
    const entScale = document.createElement("div");
    entScale.style.cssText = "color:var(--text-muted);font-size:11px;margin-top:2px;";
    entScale.textContent = "Scale: 0.0 (plain text) → 8.0 (encrypted/random) — ransomware typically > 7.5";
    entInfo.appendChild(entDesc);
    entInfo.appendChild(entScale);
    entFlex.appendChild(entNum);
    entFlex.appendChild(entInfo);
    overallDiv.appendChild(entFlex);
    body.appendChild(overallDiv);

    const sections = entropy.sections || [];
    if (sections.length > 0) {
      const hdr = document.createElement("div");
      hdr.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;margin-bottom:8px;";
      hdr.textContent = "PE Section Entropy";
      body.appendChild(hdr);
      const rows = sections.map(s => {
        const flags = [];
        if (s.wx_section) flags.push({text: "W+X", cls: "tag-red"});
        if (s.suspicious_name) flags.push({text: "PACKER", cls: "tag-red"});
        const sColor = s.level === "CRITICAL" ? "var(--red)" : s.level === "HIGH" ? "var(--orange)" : s.level === "MEDIUM" ? "var(--yellow)" : "var(--text-muted)";
        const flagsEl = document.createElement("div");
        flagsEl.className = "tag-list";
        if (flags.length === 0) {
          flagsEl.appendChild(Object.assign(document.createElement("span"), {className:"tag",textContent:s.level||""}));
        } else {
          flags.forEach(f => flagsEl.appendChild(Object.assign(document.createElement("span"), {className:`tag ${f.cls}`,textContent:f.text})));
        }
        const entEl = document.createElement("span");
        entEl.style.color = sColor;
        entEl.textContent = s.entropy;
        return [s.name || "?", formatBytes(s.raw_size||0), entEl, flagsEl];
      });
      body.appendChild(makeTable(["Section", "Size", "Entropy", "Flags"], rows));
    }
  }));

  // 8. PE Analysis
  const pe = data.pe_analysis;
  if (pe) {
    const peHasRisk = pe.ransomware_indicators && pe.ransomware_indicators.length > 0;
    const peBadge = peHasRisk ? makeBadge("SUSPICIOUS", "high") : makeBadge("ANALYZED", "info");
    container.appendChild(makeCard("⬡", "PE / Import Analysis", peBadge, body => {
      if (pe.ransomware_indicators && pe.ransomware_indicators.length > 0) {
        const warn = document.createElement("div");
        warn.style.cssText = "background:rgba(248,81,73,0.08);border:1px solid var(--red);border-radius:4px;padding:10px 12px;margin-bottom:12px;";
        const title = document.createElement("div");
        title.style.cssText = "color:var(--red);font-weight:700;margin-bottom:6px;font-size:12px;";
        title.textContent = "Ransomware / Threat Indicators";
        warn.appendChild(title);
        const ul = document.createElement("ul");
        ul.className = "indicators";
        pe.ransomware_indicators.forEach(ind => {
          const li = document.createElement("li");
          li.className = "indicator-item";
          const b = document.createElement("span");
          b.className = "indicator-bullet";
          b.textContent = "▸";
          li.appendChild(b);
          li.appendChild(document.createTextNode(ind));
          ul.appendChild(li);
        });
        warn.appendChild(ul);
        body.appendChild(warn);
      }

      // Suspicious imports by category
      const suspicious = pe.suspicious || {};
      const cats = Object.entries(suspicious);
      if (cats.length > 0) {
        const hdr = document.createElement("div");
        hdr.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;margin-bottom:8px;";
        hdr.textContent = "Suspicious Import Categories";
        body.appendChild(hdr);
        cats.forEach(([cat, apis]) => {
          const section = document.createElement("div");
          section.style.marginBottom = "10px";
          const lbl = document.createElement("div");
          const catColors = {crypto:"tag-red",process_injection:"tag-red",anti_analysis:"tag-orange",network:"tag-blue",persistence:"tag-orange",privilege_escalation:"tag-red",file_enumeration:"tag-orange",file_destruction:"tag-red",keylogger:"tag-red"};
          const cls = catColors[cat] || "tag-orange";
          lbl.style.cssText = "margin-bottom:6px;display:flex;align-items:center;gap:8px;";
          const catBadge = document.createElement("span");
          catBadge.className = `tag ${cls}`;
          catBadge.textContent = cat.replace(/_/g, " ").toUpperCase();
          lbl.appendChild(catBadge);
          section.appendChild(lbl);
          const tags = document.createElement("div");
          tags.className = "tag-list";
          (apis || []).forEach(api => {
            const t = document.createElement("span");
            t.className = "tag";
            t.textContent = api;
            tags.appendChild(t);
          });
          section.appendChild(tags);
          body.appendChild(section);
        });
      }

      if (pe.dlls && pe.dlls.length > 0) {
        const hdr2 = document.createElement("div");
        hdr2.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;margin:12px 0 8px;";
        hdr2.textContent = `DLLs Referenced (${pe.dll_count})`;
        body.appendChild(hdr2);
        const tags = document.createElement("div");
        tags.className = "tag-list";
        pe.dlls.forEach(dll => {
          const t = document.createElement("span");
          t.className = "tag";
          t.textContent = dll;
          tags.appendChild(t);
        });
        body.appendChild(tags);
      }
    }));
  }

  // 9. Script Analysis
  const script = data.script_analysis;
  if (script) {
    const sLevel = script.risk_score >= 60 ? "critical" : script.risk_score >= 30 ? "high" : script.risk_score >= 15 ? "medium" : "low";
    container.appendChild(makeCard("⬡", "Script Analysis", makeBadge(`${script.script_type.toUpperCase()} · SCORE ${script.risk_score}`, sLevel), body => {
      if (script.indicators && script.indicators.length > 0) {
        const ul = document.createElement("ul");
        ul.className = "indicators";
        script.indicators.forEach(ind => {
          const li = document.createElement("li");
          li.className = "indicator-item";
          const b = document.createElement("span");
          b.className = "indicator-bullet";
          b.textContent = "▸";
          li.appendChild(b);
          li.appendChild(document.createTextNode(ind));
          ul.appendChild(li);
        });
        body.appendChild(ul);
      }
      if (script.urls_found && script.urls_found.length > 0) {
        const hdr = document.createElement("div");
        hdr.style.cssText = "color:var(--text-muted);font-size:11px;margin-top:12px;margin-bottom:6px;text-transform:uppercase;font-weight:600;";
        hdr.textContent = "Hardcoded URLs";
        body.appendChild(hdr);
        const rows = script.urls_found.map(u => [u]);
        body.appendChild(makeTable(["URL"], rows));
      }
    }));
  }

  // 10. Archive Analysis
  const archive = data.archive_analysis;
  if (archive && archive.scanned) {
    const archiveBadge = archive.suspicious_files && archive.suspicious_files.length > 0
      ? makeBadge(`${archive.suspicious_files.length} SUSPICIOUS`, "high") : makeBadge("CLEAN", "clean");
    container.appendChild(makeCard("⬡", `Archive Contents (${archive.file_count || 0} files)`, archiveBadge, body => {
      if (archive.error) {
        body.textContent = archive.error;
        return;
      }
      if (archive.suspicious_files && archive.suspicious_files.length > 0) {
        const warn = document.createElement("div");
        warn.style.cssText = "background:rgba(248,81,73,0.08);border:1px solid var(--red);border-radius:4px;padding:10px 12px;margin-bottom:12px;";
        const warnTitle = document.createElement("div");
        warnTitle.style.cssText = "color:var(--red);font-weight:700;margin-bottom:8px;font-size:12px;";
        warnTitle.textContent = "Suspicious Files Inside Archive";
        warn.appendChild(warnTitle);
        archive.suspicious_files.forEach(sf => {
          const row = document.createElement("div");
          row.style.cssText = "margin-bottom:6px;font-size:12px;";
          const nameEl = document.createElement("div");
          nameEl.style.color = "var(--orange)";
          nameEl.textContent = sf.name;
          row.appendChild(nameEl);
          (sf.flags || []).forEach(flag => {
            const f = document.createElement("div");
            f.style.cssText = "color:var(--text-muted);font-size:11px;margin-left:12px;";
            f.textContent = "▸ " + flag;
            row.appendChild(f);
          });
          warn.appendChild(row);
        });
        body.appendChild(warn);
      }
      const hdr = document.createElement("div");
      hdr.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;margin-bottom:8px;";
      hdr.textContent = `All Contents (${(archive.contents||[]).length} shown)`;
      body.appendChild(hdr);
      const pre = document.createElement("pre");
      pre.textContent = (archive.contents || []).join("\n");
      body.appendChild(pre);
    }));
  }

  // 11. PDF Analysis
  const pdf = data.pdf_analysis;
  if (pdf && !pdf.error) {
    const pdfScore = pdf.risk_score || 0;
    const pdfLevel = pdfScore >= 70 ? "critical" : pdfScore >= 40 ? "high" : pdfScore >= 15 ? "medium" : "low";
    const pdfBadge = pdfScore > 0 ? makeBadge(`RISK SCORE ${pdfScore}`, pdfLevel) : makeBadge("CLEAN", "clean");
    container.appendChild(makeCard("⬡", "PDF Structure Analysis", pdfBadge, body => {

      // Overview
      body.appendChild(makeKV([
        ["PDF version", pdf.version],
        ["Object count", pdf.object_count],
        ["Encrypted", pdf.is_encrypted ? "Yes" : "No"],
        ["Has AcroForm", pdf.has_acroform ? "Yes" : "No"],
        ["Has object streams (/ObjStm)", pdf.has_object_streams ? "Yes (can hide objects)" : "No"],
      ]));

      // Risk indicators
      if (pdf.indicators && pdf.indicators.length > 0) {
        const hdr = document.createElement("div");
        hdr.style.cssText = "color:var(--red);font-size:11px;font-weight:600;text-transform:uppercase;margin:12px 0 8px;";
        hdr.textContent = "Threat Indicators";
        body.appendChild(hdr);
        const ul = document.createElement("ul");
        ul.className = "indicators";
        pdf.indicators.forEach(ind => {
          const li = document.createElement("li");
          li.className = "indicator-item";
          const b = document.createElement("span");
          b.className = "indicator-bullet";
          b.textContent = "▸";
          li.appendChild(b);
          li.appendChild(document.createTextNode(ind));
          ul.appendChild(li);
        });
        body.appendChild(ul);
      }

      // JavaScript details
      const js = pdf.javascript || {};
      if (js.found) {
        const jsHdr = document.createElement("div");
        jsHdr.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;margin:12px 0 8px;";
        jsHdr.textContent = `Embedded JavaScript (${js.block_count} block(s))`;
        body.appendChild(jsHdr);
        if (js.threat_patterns && js.threat_patterns.length > 0) {
          const tags = document.createElement("div");
          tags.className = "tag-list";
          tags.style.marginBottom = "8px";
          js.threat_patterns.forEach(p => {
            const t = document.createElement("span");
            t.className = "tag tag-red";
            t.textContent = p;
            tags.appendChild(t);
          });
          body.appendChild(tags);
        }
        if (js.urls_in_js && js.urls_in_js.length > 0) {
          const urlHdr = document.createElement("div");
          urlHdr.style.cssText = "color:var(--text-muted);font-size:11px;margin-bottom:6px;";
          urlHdr.textContent = "URLs inside JavaScript:";
          body.appendChild(urlHdr);
          js.urls_in_js.forEach(u => {
            const d = document.createElement("div");
            d.style.cssText = "color:var(--orange);font-size:12px;word-break:break-all;margin-bottom:2px;";
            d.textContent = u;
            body.appendChild(d);
          });
        }
      }

      // Actions
      const actions = pdf.actions || {};
      const activeActions = Object.entries(actions).filter(([,v]) => v);
      if (activeActions.length > 0) {
        const actHdr = document.createElement("div");
        actHdr.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;margin:12px 0 8px;";
        actHdr.textContent = "PDF Actions Present";
        body.appendChild(actHdr);
        const tags = document.createElement("div");
        tags.className = "tag-list";
        const dangerousActions = new Set(["launch_action","open_action","goto_remote","import_data","submit_form","xfa_forms"]);
        activeActions.forEach(([k]) => {
          const t = document.createElement("span");
          t.className = dangerousActions.has(k) ? "tag tag-red" : "tag tag-orange";
          t.textContent = k.replace(/_/g, " ");
          tags.appendChild(t);
        });
        body.appendChild(tags);
      }

      // Embedded files
      const emb = pdf.embedded_files || {};
      if (emb.found) {
        const embHdr = document.createElement("div");
        embHdr.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;margin:12px 0 8px;";
        embHdr.textContent = `Embedded Files (${emb.count})`;
        body.appendChild(embHdr);
        if (emb.filenames && emb.filenames.length > 0) {
          emb.filenames.forEach(f => {
            const d = document.createElement("div");
            d.style.cssText = "color:var(--orange);font-size:12px;margin-bottom:2px;";
            d.textContent = f;
            body.appendChild(d);
          });
        }
      }

      // URIs
      if (pdf.uris && pdf.uris.length > 0) {
        const uriHdr = document.createElement("div");
        uriHdr.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;margin:12px 0 8px;";
        uriHdr.textContent = `URIs (${pdf.uris.length})`;
        body.appendChild(uriHdr);
        pdf.uris.forEach(u => {
          const d = document.createElement("div");
          d.style.cssText = "color:var(--accent);font-size:12px;word-break:break-all;margin-bottom:2px;cursor:pointer;";
          d.textContent = u;
          d.title = "Click to copy";
          d.addEventListener("click", () => copyToClipboard(u, d));
          body.appendChild(d);
        });
      }

      // Stream filters
      const streams = pdf.streams || {};
      if (streams.suspicious_filters && streams.suspicious_filters.length > 0) {
        const sfHdr = document.createElement("div");
        sfHdr.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;margin:12px 0 8px;";
        sfHdr.textContent = "Suspicious Stream Filters";
        body.appendChild(sfHdr);
        const tags = document.createElement("div");
        tags.className = "tag-list";
        streams.suspicious_filters.forEach(f => {
          const t = document.createElement("span");
          t.className = "tag tag-orange";
          t.textContent = f;
          tags.appendChild(t);
        });
        body.appendChild(tags);
      }

      // Keyword counts
      const kw = pdf.keyword_hits || {};
      if (Object.keys(kw).length > 0) {
        const kwHdr = document.createElement("div");
        kwHdr.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;margin:12px 0 8px;";
        kwHdr.textContent = "Suspicious PDF Keywords";
        body.appendChild(kwHdr);
        const rows = Object.entries(kw).map(([k, v]) => [k, v]);
        body.appendChild(makeTable(["Keyword", "Count"], rows));
      }
    }));
  }

  // 12. MalwareBazaar
  const mb = data.malwarebazaar || {};
  if (mb.found || mb.error) {
    const mbBadge = mb.found ? makeBadge("KNOWN MALWARE", "critical") : makeBadge("NOT FOUND", "info");
    container.appendChild(makeCard("⬡", "MalwareBazaar (abuse.ch)", mbBadge, body => {
      if (mb.error) { body.textContent = mb.error; return; }
      if (!mb.found) { body.textContent = "Hash not found in MalwareBazaar database."; return; }
      body.appendChild(makeKV([
        ["Malware family", mb.signature],
        ["File name", mb.file_name],
        ["File type", mb.file_type],
        ["First seen", mb.first_seen],
        ["Tags", (mb.tags || []).join(", ")],
        ["Reporter", mb.reporter],
        ["Origin country", mb.origin_country],
        ["Permalink", mb.permalink],
      ]));
    }));
  }

  // 12. Strings
  const strings = data.strings || {};
  container.appendChild(makeCard("⬡", "Extracted Strings", null, body => {
    const sections = [
      ["Suspicious Commands", strings.suspicious_commands, "tag-red"],
      ["URLs", strings.urls, "tag-blue"],
      ["IP Addresses", strings.ips, "tag-blue"],
      ["Registry Keys", strings.registry_keys, "tag-orange"],
      ["File Paths", strings.file_paths, "tag-purple"],
      ["Base64 Blobs", strings.base64_blobs, "tag-orange"],
    ];

    let hasContent = false;
    sections.forEach(([label, items, tagClass]) => {
      if (!items || items.length === 0) return;
      hasContent = true;

      const section = document.createElement("div");
      section.style.marginBottom = "16px";

      const lbl = document.createElement("div");
      lbl.style.cssText = "color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;";
      lbl.textContent = `${label} (${items.length})`;
      section.appendChild(lbl);

      const list = document.createElement("div");
      list.className = "tag-list";
      items.forEach(item => {
        const span = document.createElement("span");
        span.className = `tag ${tagClass}`;
        span.style.cursor = "pointer";
        span.title = "Click to copy";
        const display = item.length > 80 ? item.substring(0, 80) + "…" : item;
        span.textContent = display;
        span.addEventListener("click", () => copyToClipboard(item, span));
        list.appendChild(span);
      });
      section.appendChild(list);
      body.appendChild(section);
    });

    if (!hasContent) {
      body.textContent = "No notable strings found.";
    }

    if (strings.total_strings) {
      const total = document.createElement("div");
      total.style.cssText = "color:var(--text-dim);font-size:11px;margin-top:8px;";
      total.textContent = `Total strings extracted: ${strings.total_strings}`;
      body.appendChild(total);
    }
  }));

  return container;
}

function _vtBadge(vt) {
  if (vt.error) return makeBadge("N/A", "info");
  if (!vt.found) return makeBadge("NOT FOUND", "info");
  const mal = vt.malicious || 0;
  if (mal > 5) return makeBadge(`${mal} DETECTIONS`, "critical");
  if (mal > 0) return makeBadge(`${mal} DETECTIONS`, "high");
  if ((vt.suspicious || 0) > 0) return makeBadge("SUSPICIOUS", "medium");
  return makeBadge("CLEAN", "clean");
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}
