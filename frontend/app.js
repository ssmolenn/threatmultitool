// Tab switching
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(s => s.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

// ---- Shared helpers ----

function setupDropZone(dropId, inputId, infoId, nameId, hashPreviewId, onFile) {
  const drop = document.getElementById(dropId);
  const input = document.getElementById(inputId);
  const info = document.getElementById(infoId);
  const nameEl = document.getElementById(nameId);
  const hashEl = hashPreviewId ? document.getElementById(hashPreviewId) : null;

  drop.addEventListener("click", e => {
    if (e.target.closest(".file-selected")) return;
    input.click();
  });

  ["dragenter", "dragover"].forEach(ev => {
    drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("drag-over"); });
  });
  ["dragleave", "drop"].forEach(ev => {
    drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("drag-over"); });
  });
  drop.addEventListener("drop", e => {
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  });
  input.addEventListener("change", () => {
    if (input.files[0]) handleFile(input.files[0]);
  });

  function handleFile(file) {
    nameEl.textContent = file.name;
    info.hidden = false;
    drop.querySelector(".upload-inner").style.display = "none";

    if (hashEl) {
      // Compute SHA-256 client-side for preview
      file.arrayBuffer().then(buf => {
        crypto.subtle.digest("SHA-256", buf).then(hash => {
          const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
          hashEl.textContent = "SHA-256: " + hex;
        });
      });
    }
    onFile(file);
  }

  return () => {
    input.value = "";
    info.hidden = true;
    if (nameEl) nameEl.textContent = "";
    if (hashEl) hashEl.textContent = "";
    drop.querySelector(".upload-inner").style.display = "";
  };
}

// ---- EMAIL ----
let emailFile = null;
const emailSubmit = document.getElementById("email-submit");

const clearEmail = setupDropZone("email-drop", "email-input", "email-file-info", "email-file-name", null, file => {
  emailFile = file;
  emailSubmit.disabled = false;
});

document.getElementById("email-clear").addEventListener("click", e => {
  e.stopPropagation();
  emailFile = null;
  emailSubmit.disabled = true;
  document.getElementById("email-results").innerHTML = "";
  clearEmail();
});

emailSubmit.addEventListener("click", async () => {
  if (!emailFile) return;
  emailSubmit.disabled = true;
  emailSubmit.innerHTML = '<span class="spinner"></span>Analyzing…';

  const fd = new FormData();
  fd.append("file", emailFile);

  try {
    const resp = await fetch("/api/email/analyze", { method: "POST", body: fd });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Server error");
    document.getElementById("email-results").innerHTML = "";
    document.getElementById("email-results").appendChild(renderEmailResults(data));
  } catch (err) {
    showError("email-results", err.message);
  } finally {
    emailSubmit.disabled = false;
    emailSubmit.textContent = "Analyze Email";
  }
});

// ---- FILE ----
let fileFile = null;
const fileSubmit = document.getElementById("file-submit");

const clearFile = setupDropZone("file-drop", "file-input", "file-file-info", "file-file-name", "file-hash-preview", file => {
  fileFile = file;
  fileSubmit.disabled = false;
});

document.getElementById("file-clear").addEventListener("click", e => {
  e.stopPropagation();
  fileFile = null;
  fileSubmit.disabled = true;
  document.getElementById("file-results").innerHTML = "";
  clearFile();
});

fileSubmit.addEventListener("click", async () => {
  if (!fileFile) return;
  fileSubmit.disabled = true;
  fileSubmit.innerHTML = '<span class="spinner"></span>Scanning…';

  const fd = new FormData();
  fd.append("file", fileFile);

  try {
    const resp = await fetch("/api/file/analyze", { method: "POST", body: fd });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Server error");
    document.getElementById("file-results").innerHTML = "";
    document.getElementById("file-results").appendChild(renderFileResults(data));
  } catch (err) {
    showError("file-results", err.message);
  } finally {
    fileSubmit.disabled = false;
    fileSubmit.textContent = "Scan File";
  }
});

// ---- Shared UI helpers ----

function showError(containerId, message) {
  const div = document.createElement("div");
  div.className = "error-box";
  div.textContent = "Error: " + message;
  document.getElementById(containerId).appendChild(div);
}

// Expose to component scripts
window.makeCard = function(icon, title, badge, bodyFn, startOpen = false) {
  const card = document.createElement("div");
  card.className = "result-card";

  const hdr = document.createElement("div");
  hdr.className = "card-header" + (startOpen ? " open" : "");

  const titleDiv = document.createElement("div");
  titleDiv.className = "card-title";
  const iconSpan = document.createElement("span");
  iconSpan.className = "card-icon";
  iconSpan.textContent = icon;
  const titleSpan = document.createElement("span");
  titleSpan.textContent = title;
  titleDiv.appendChild(iconSpan);
  titleDiv.appendChild(titleSpan);
  if (badge) titleDiv.appendChild(badge);

  const chevron = document.createElement("span");
  chevron.className = "card-chevron";
  chevron.textContent = "▶";

  hdr.appendChild(titleDiv);
  hdr.appendChild(chevron);

  const body = document.createElement("div");
  body.className = "card-body" + (startOpen ? " open" : "");
  bodyFn(body);

  hdr.addEventListener("click", () => {
    hdr.classList.toggle("open");
    body.classList.toggle("open");
  });

  card.appendChild(hdr);
  card.appendChild(body);
  return card;
};

window.makeBadge = function(text, level) {
  const span = document.createElement("span");
  span.className = `badge badge-${level.toLowerCase()}`;
  span.textContent = text;
  return span;
};

window.makeKV = function(pairs) {
  const grid = document.createElement("div");
  grid.className = "kv-grid";
  for (const [key, value] of pairs) {
    if (!value && value !== 0) continue;
    const row = document.createElement("div");
    row.className = "kv-row";
    const k = document.createElement("div");
    k.className = "kv-key";
    k.textContent = key;
    const v = document.createElement("div");
    v.className = "kv-val";
    v.textContent = value;
    row.appendChild(k);
    row.appendChild(v);
    grid.appendChild(row);
  }
  return grid;
};

window.makeTable = function(headers, rows) {
  const t = document.createElement("table");
  t.className = "data-table";
  const thead = t.createTHead();
  const hrow = thead.insertRow();
  headers.forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    hrow.appendChild(th);
  });
  const tbody = t.createTBody();
  rows.forEach(row => {
    const tr = tbody.insertRow();
    row.forEach(cell => {
      const td = tr.insertCell();
      if (cell && typeof cell === "object" && cell.nodeType) {
        td.appendChild(cell);
      } else {
        td.textContent = cell ?? "—";
      }
    });
  });
  return t;
};

window.copyToClipboard = function(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = "✓";
    setTimeout(() => { btn.textContent = orig; }, 1500);
  });
};
