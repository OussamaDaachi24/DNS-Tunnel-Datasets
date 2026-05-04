const API = {
  features: "/api/features",
  samples:  "/api/samples",
  predict:  "/api/predict",
};

let FEATURES = [];   // list of feature names (model order)
let GROUPS   = [];   // [{title, fields}]
let SAMPLES  = [];   // [{label, source, pcap_file, features:{...}}]

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

async function init() {
  const [feats, samps] = await Promise.all([
    fetch(API.features).then(r => r.json()),
    fetch(API.samples ).then(r => r.json()),
  ]);
  FEATURES = feats.features;
  GROUPS   = feats.groups;
  SAMPLES  = samps.samples;

  renderGroups();
  populateSampleSelect();

  $("#btn-fill").addEventListener("click", onFill);
  $("#btn-zero").addEventListener("click", onZero);
  $("#feat-form").addEventListener("submit", onSubmit);
}

function renderGroups() {
  const root = $("#groups");
  root.innerHTML = "";
  for (const g of GROUPS) {
    const card = document.createElement("div");
    card.className = "group";
    card.innerHTML = `<h3>${g.title}</h3>`;
    for (const f of g.fields) {
      const row = document.createElement("div");
      row.className = "field";
      row.innerHTML = `
        <label for="f-${f}">${f}</label>
        <input id="f-${f}" name="${f}" type="number" step="any" value="0" />
      `;
      card.appendChild(row);
    }
    root.appendChild(card);
  }
}

function populateSampleSelect() {
  const sel = $("#sample-select");
  // 8 tunnel first, then 7 benign
  SAMPLES.forEach((s, i) => {
    const opt = document.createElement("option");
    opt.value = String(i);
    opt.textContent = `${i + 1}. ${s.label} — ${s.source} / ${s.pcap_file}`;
    sel.appendChild(opt);
  });
}

function onFill() {
  const idx = $("#sample-select").value;
  if (idx === "") return;
  const sample = SAMPLES[Number(idx)];
  for (const f of FEATURES) {
    const el = $(`#f-${cssEscape(f)}`);
    if (el) el.value = String(sample.features[f] ?? 0);
  }
  $("#sample-meta").textContent =
    `loaded: ${sample.label} window from ${sample.pcap_file}`;
  $("#truth").textContent = `Ground-truth label for this window: ${sample.label}`;
  $("#truth").dataset.truth = sample.label;
}

function onZero() {
  for (const f of FEATURES) {
    const el = $(`#f-${cssEscape(f)}`);
    if (el) el.value = "0";
  }
  $("#sample-meta").textContent = "";
  $("#truth").textContent = "";
  delete $("#truth").dataset.truth;
}

async function onSubmit(ev) {
  ev.preventDefault();
  const features = {};
  for (const f of FEATURES) {
    const el = $(`#f-${cssEscape(f)}`);
    const v = parseFloat(el.value);
    features[f] = Number.isFinite(v) ? v : 0;
  }
  const btn = $("#btn-classify");
  btn.disabled = true; btn.textContent = "classifying…";
  try {
    const res = await fetch(API.predict, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ features }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || res.statusText);
    }
    const data = await res.json();
    showResult(data);
  } catch (e) {
    alert("Prediction failed: " + e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Classify window";
  }
}

function showResult(d) {
  const result  = $("#result");
  const verdict = $("#verdict");
  const prob    = $("#prob");
  const bar     = $("#prob-bar");

  result.classList.remove("hidden");
  const isTunnel = d.decision === "TUNNEL";
  verdict.textContent = d.decision;
  verdict.className   = isTunnel ? "tunnel" : "benign";
  prob.textContent    = `P(tunnel) = ${d.p_tunnel.toFixed(4)}`;

  bar.className = isTunnel ? "tunnel" : "benign";
  bar.style.width = `${(d.p_tunnel * 100).toFixed(1)}%`;

  const tbody = $("#base-table tbody");
  tbody.innerHTML = "";
  const labels = { lr: "Logistic Regression", rf: "Random Forest", gb: "Gradient Boosting" };
  for (const [k, v] of Object.entries(d.base_probs)) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${labels[k] || k}</td><td>${v.toFixed(4)}</td>`;
    tbody.appendChild(tr);
  }

  const truth = $("#truth").dataset.truth;
  if (truth) {
    const ok = (truth === "TUNNEL") === isTunnel;
    $("#truth").textContent =
      `Ground truth: ${truth} — prediction is ${ok ? "✓ correct" : "✗ wrong"}`;
  }

  result.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Some feature names contain underscores only, but escape anyway.
function cssEscape(s) {
  return (window.CSS && CSS.escape) ? CSS.escape(s) : s.replace(/[^a-zA-Z0-9_-]/g, "\\$&");
}

init().catch(e => {
  document.body.innerHTML =
    `<pre style="color:#ff6b6b;padding:24px;">Failed to initialize app: ${e.message}</pre>`;
});
