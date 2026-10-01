const MISSING = "Open this in the Custody window.";

function showError(message) {
  const el = document.getElementById("error");
  el.hidden = !message;
  el.textContent = message || "";
}

function invokeFn() {
  if (!window.__TAURI__ || !window.__TAURI__.core || !window.__TAURI__.core.invoke) {
    return null;
  }
  return window.__TAURI__.core.invoke;
}

async function call(cmd, args) {
  const invoke = invokeFn();
  if (!invoke) {
    showError(MISSING);
    throw new Error(MISSING);
  }
  showError("");
  try {
    return await invoke(cmd, args || {});
  } catch (err) {
    const message = typeof err === "string" ? err : (err && err.message) || String(err);
    showError(message);
    throw err;
  }
}

function rootValue() {
  return document.getElementById("root").value;
}

function who(entry) {
  if (entry.action === "transfer") {
    return (entry.from || "-") + " → " + (entry.to || "-");
  }
  return entry.custodian || "-";
}

function renderLog(opened) {
  const label = document.getElementById("case-id");
  const list = document.getElementById("log");
  list.replaceChildren();
  if (!opened) {
    label.textContent = "";
    return;
  }
  label.textContent = opened.case_id;
  if (!opened.entries.length) {
    const empty = document.createElement("li");
    empty.textContent = "No entries.";
    empty.style.cursor = "default";
    list.appendChild(empty);
    return;
  }
  for (const entry of opened.entries) {
    const li = document.createElement("li");
    li.style.cursor = "default";
    const num = document.createElement("span");
    num.className = "num";
    num.textContent = entry.seq + "  " + entry.timestamp + "  " + entry.action;
    const meta = document.createElement("span");
    meta.className = "meta";
    const hash = (entry.entry_hash || "").slice(0, 12);
    meta.textContent = entry.file + "  " + who(entry) + "  " + hash;
    li.append(num, meta);
    list.appendChild(li);
  }
}

function clearVerify() {
  document.getElementById("verify-out").replaceChildren();
}

function renderVerify(result) {
  const out = document.getElementById("verify-out");
  out.replaceChildren();
  const pass = result.chain_ok && result.files.every((file) => file.ok);
  const head = document.createElement("p");
  head.textContent = pass ? "PASS" : "FAIL";
  out.appendChild(head);
  for (const err of result.chain_errors) {
    const line = document.createElement("p");
    line.className = "hint";
    line.textContent = err;
    out.appendChild(line);
  }
  if (!result.files.length) return;
  const list = document.createElement("ul");
  list.className = "cases";
  for (const file of result.files) {
    const li = document.createElement("li");
    li.style.cursor = "default";
    const num = document.createElement("span");
    num.className = "num";
    num.textContent = (file.ok ? "PASS" : "FAIL") + "  " + file.file;
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = file.detail;
    li.append(num, meta);
    list.appendChild(li);
  }
  out.appendChild(list);
}

async function refresh() {
  const root = rootValue();
  const opened = await call("open_case", { root });
  renderLog(opened);
  document.getElementById("report").textContent = await call("report_text", { root });
  clearVerify();
}

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (form.matches("#open-case")) {
    event.preventDefault();
    try {
      await refresh();
    } catch (_) {}
    return;
  }
  if (form.matches("#init-case")) {
    event.preventDefault();
    try {
      await call("init_case", {
        root: rootValue(),
        caseId: form.elements.case_id.value,
      });
      form.reset();
      await refresh();
    } catch (_) {}
    return;
  }
  if (form.matches("#intake-form")) {
    event.preventDefault();
    try {
      await call("intake", {
        root: rootValue(),
        file: form.elements.file.value,
        custodian: form.elements.custodian.value,
        notes: form.elements.notes.value,
      });
      form.reset();
      await refresh();
    } catch (_) {}
    return;
  }
  if (form.matches("#transfer-form")) {
    event.preventDefault();
    try {
      await call("transfer", {
        root: rootValue(),
        file: form.elements.file.value,
        from: form.elements.from.value,
        to: form.elements.to.value,
        notes: form.elements.notes.value,
      });
      form.reset();
      await refresh();
    } catch (_) {}
  }
});

document.getElementById("verify-btn").addEventListener("click", async () => {
  try {
    renderVerify(await call("verify_case", { root: rootValue() }));
  } catch (_) {}
});

if (!invokeFn()) {
  showError(MISSING);
}
