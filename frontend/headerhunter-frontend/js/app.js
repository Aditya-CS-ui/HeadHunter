const API_ENDPOINT = "/api/analyze";
const SAMPLES_ENDPOINT = "/api/samples";

const $ = (id) => document.getElementById(id);
const scanForm = $("scanForm");
const headersInput = $("headersInput");
const analyzeBtn = $("analyzeBtn");
const sampleSelect = $("sampleSelect");
const loadSampleBtn = $("loadSampleBtn");
const scanStatus = $("scanStatus");
const dashboard = $("dashboard");
const emptyState = $("emptyState");
const scoreRing = $("scoreRing");
const scoreValue = $("scoreValue");
const scoreNote = $("scoreNote");
const findingCount = $("findingCount");
const findingList = $("findingList");
const aiContent = $("aiContent");
const aiWarning = $("aiWarning");

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setLoading(loading) {
  analyzeBtn.disabled = loading;
  loadSampleBtn.disabled = loading;
  analyzeBtn.classList.toggle("loading", loading);
  analyzeBtn.querySelector(".btn-label").textContent = loading ? "Analyzing..." : "Analyze";
  scanStatus.innerHTML = loading
    ? '<span class="loading-indicator" aria-hidden="true"></span>Analyzing response headers. The first AI analysis can take 30–60 seconds.'
    : "";
}

function showError(message) {
  scanStatus.textContent = message;
  scanStatus.classList.add("error");
}

function clearStatusError() {
  scanStatus.classList.remove("error");
}

function renderScore(score, note) {
  const numericScore = Number(score);
  const angle = Number.isFinite(numericScore) ? numericScore * 3.6 : 0;
  scoreRing.style.setProperty("--score-angle", `${angle}deg`);
  scoreValue.textContent = score ?? "—";
  scoreNote.textContent = note || "This score is an estimate based on the configured security checks.";
}

function severityClass(severity) {
  const normalized = String(severity || "low").toLowerCase();
  return ["high", "medium", "low"].includes(normalized) ? normalized : "low";
}

function statusClass(status) {
  const normalized = String(status || "").toLowerCase();
  return normalized === "missing" || normalized === "weak" ? normalized : "weak";
}

function renderFindings(findings) {
  const items = Array.isArray(findings) ? findings : [];
  findingCount.textContent = items.length;

  if (!items.length) {
    findingList.innerHTML = `
      <article class="finding-card no-issues">
        <span class="finding-icon good">✓</span>
        <div>
          <div class="finding-title">No issues found</div>
          <p class="finding-description">The deterministic security checks did not identify any findings.</p>
        </div>
      </article>`;
    return;
  }

  findingList.innerHTML = items.map((item) => {
    const severity = severityClass(item.severity);
    const status = statusClass(item.status);
    return `
      <article class="finding-card">
        <span class="finding-icon ${severity}">${severity === "high" ? "!" : severity === "medium" ? "!" : "i"}</span>
        <div>
          <div class="finding-title">
            ${escapeHtml(item.header)}
            <span class="severity-badge ${severity}">${escapeHtml(item.severity)}</span>
            <span class="status-badge ${status}">${escapeHtml(item.status)}</span>
          </div>
          <p class="finding-description">${escapeHtml(item.message)}</p>
        </div>
      </article>`;
  }).join("");
}

function renderAI(explanations, aiError) {
  if (typeof explanations === "string" && explanations.trim()) {
    aiWarning.classList.add("hidden");
    aiContent.classList.remove("hidden");
    aiContent.innerHTML = `<div class="ai-explanation">${escapeHtml(explanations)}</div>`;
    return;
  }

  aiContent.classList.add("hidden");
  aiWarning.classList.remove("hidden");
  aiWarning.textContent = aiError || "AI explanations are unavailable right now.";
}

function renderResults(data) {
  renderScore(data.score, data.scoreNote);
  renderFindings(data.findings);
  renderAI(data.explanations, data.aiError);

  dashboard.classList.remove("hidden");
  emptyState.classList.add("hidden");
  dashboard.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function analyze(headers) {
  const response = await fetch(API_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ headers })
  });

  let data = null;
  try {
    data = await response.json();
  } catch {
    // Keep the status-specific error below when the server returns no JSON.
  }

  if (!response.ok) {
    if (response.status === 400 && data?.error) {
      throw new Error(data.error);
    }
    throw new Error(`Request failed with status ${response.status}.`);
  }

  return data;
}

async function loadSamples() {
  try {
    const response = await fetch(SAMPLES_ENDPOINT);
    if (!response.ok) throw new Error(`Samples request failed with status ${response.status}.`);

    const data = await response.json();
    const samples = Array.isArray(data) ? data : Array.isArray(data.samples) ? data.samples : [];

    sampleSelect.innerHTML = '<option value="">Choose a sample...</option>';
    samples.forEach((sample, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = sample.title;
      option.dataset.headers = sample.headers;
      sampleSelect.appendChild(option);
    });

    sampleSelect.disabled = samples.length === 0;
    loadSampleBtn.disabled = samples.length === 0;
  } catch (error) {
    console.warn("Could not load samples:", error);
    sampleSelect.innerHTML = '<option value="">Samples unavailable</option>';
    sampleSelect.disabled = true;
    loadSampleBtn.disabled = true;
  }
}

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const headers = headersInput.value.trim();

  if (!headers) {
    clearStatusError();
    showError("Please paste HTTP response headers before analyzing.");
    headersInput.focus();
    return;
  }

  clearStatusError();
  setLoading(true);

  try {
    const result = await analyze(headers);
    renderResults(result);
    scanStatus.textContent = "Analysis complete.";
  } catch (error) {
    console.error(error);
    showError(error instanceof TypeError
      ? "Cannot reach the HeaderHunter server. Make sure the backend is running."
      : error.message || "The analysis could not be completed.");
  } finally {
    setLoading(false);
  }
});

loadSampleBtn.addEventListener("click", () => {
  const option = sampleSelect.options[sampleSelect.selectedIndex];
  if (!option || !option.dataset.headers) {
    scanStatus.textContent = "Choose a sample first.";
    return;
  }

  headersInput.value = option.dataset.headers;
  scanStatus.textContent = `${option.textContent} sample loaded.`;
  clearStatusError();
  headersInput.focus();
});

loadSamples();
