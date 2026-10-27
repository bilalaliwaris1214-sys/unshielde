// All untrusted text (from emails, URLs, QR codes) is inserted with textContent only.
(function () {
  "use strict";
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const status = $("#status"), out = $("#result");

  // ---- tabs
  $$(".tab").forEach(t => t.addEventListener("click", () => {
    $$(".tab").forEach(x => { x.classList.toggle("active", x === t); x.setAttribute("aria-selected", x === t); });
    $$(".panel").forEach(p => { p.hidden = p.id !== "panel-" + t.dataset.tab; });
    out.replaceChildren(); status.textContent = ""; status.className = "status";
  }));

  const preview = $("#qr-preview");
  $("#in-qr").addEventListener("change", e => {
    const f = e.target.files[0];
    if (f) { preview.src = URL.createObjectURL(f); preview.hidden = false; } else { preview.hidden = true; }
  });

  // ---- rendering
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const tone = v => v === "PHISHING" ? "bad" : v === "SUSPICIOUS" ? "warn" : "safe";
  const color = v => `var(--${tone(v)})`;
  const ADVICE = {
    "PHISHING": "Do NOT click, reply, scan or share any code. Delete it and, if it pretends to be your bank or university, report it through their official website or number.",
    "SUSPICIOUS": "Be careful. Don't enter passwords or OTPs. Open the organisation's official website by typing the address yourself.",
    "LIKELY SAFE": "No strong phishing signs found. This is not a guarantee - still avoid sharing OTPs or passwords you were not expecting to be asked for."
  };

  function render(r, child) {
    const card = el("div", "card v-" + tone(r.verdict) + (child ? " child" : ""));
    if (r.error) { card.append(el("p", "", r.error)); return card; }
    const head = el("div", "head");
    const m = el("div", "meter"); m.style.background = `conic-gradient(${color(r.verdict)} ${r.score * 3.6}deg, var(--line) 0)`;
    m.append(el("b", "", String(r.score)));
    const info = el("div");
    const v = el("div", "verdict"); v.append(el("span", "chip", r.verdict));
    info.append(v, el("div", "target", r.kind.toUpperCase() + ": " + r.target));
    head.append(m, info); card.append(head);
    if (!child) card.append(el("div", "advice", ADVICE[r.verdict]));

    if (r.findings.length) {
      const ul = el("ul", "findings");
      r.findings.forEach(f => {
        const li = el("li"), p = el("span", "pts" + (f.weight ? "" : " zero"), f.weight ? "+" + f.weight : "info");
        const body = el("div"); body.append(el("span", "", f.message));
        if (f.evidence) body.append(el("span", "ev", f.evidence));
        li.append(p, body); ul.append(li);
      });
      card.append(ul);
    } else if (!r.children.length) {
      card.append(el("p", "", "No suspicious signals found."));
    }
    if (r.children.length) {
      card.append(el("h3", "sub", "Links found inside (" + r.children.length + ")"));
      r.children.forEach(c => card.append(render(c, true)));
    }
    return card;
  }

  // ---- actions
  async function run(kind, btn) {
    status.className = "status"; status.textContent = "Analysing..."; out.replaceChildren(); btn.disabled = true;
    try {
      let res;
      if (kind === "url" || kind === "text") {
        const val = $("#in-" + kind).value;
        res = await fetch("/api/" + kind, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ [kind]: val }) });
      } else {
        const fd = new FormData();
        const file = $(kind === "qr" ? "#in-qr" : "#in-email-file").files[0];
        if (file) fd.append("file", file);
        else if (kind === "email") {
          res = await fetch("/api/email", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ raw: $("#in-email-raw").value }) });
        } else { throw new Error("Choose an image first."); }
        if (!res) res = await fetch("/api/" + kind, { method: "POST", body: fd });
      }
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Request failed");
      status.textContent = "";
      out.append(render(data, false));
    } catch (e) {
      status.className = "status err"; status.textContent = e.message;
    } finally { btn.disabled = false; }
  }
  $$(".go").forEach(b => b.addEventListener("click", () => run(b.dataset.run, b)));
  $("#in-url").addEventListener("keydown", e => { if (e.key === "Enter") run("url", $('[data-run="url"]')); });
})();
