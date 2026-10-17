// Talks to the local Ollama server running Gemma 4.
// No API keys are used. Ollama runs on your own machine.
const OLLAMA_URL = process.env.OLLAMA_URL || "http://localhost:11434";
const MODEL = process.env.OLLAMA_MODEL || "gemma4:e2b";
const TIMEOUT_MS = 120000; // first call can be slow while the model loads

function buildPrompt(result) {
  const lines = result.findings.map(
    (f) => `- ${f.header} (${f.severity}, ${f.status}): ${f.message}`
  );

  return `You are a web security assistant helping a beginner developer.
A deterministic checker found these HTTP security header issues. Only explain these issues. Do not invent new findings.

Current estimated score: ${result.score}/100

Findings:
${lines.length ? lines.join("\n") : "- No issues found."}

For each finding, briefly explain:
1. What the security header does.
2. Why the current configuration may be risky.
3. What the potential impact could be.
4. How to fix it, with a short example configuration.

Keep the answer under 300 words. Add a note that example configurations depend on the website's requirements.`;
}

// Returns { explanations, aiError }. Never throws, so the server always responds.
async function explainFindings(result) {
  // Nothing to explain when all checks pass
  if (!result.findings || result.findings.length === 0) {
    return {
      explanations: "All checked security headers look good. Keep monitoring them as your site changes.",
      aiError: null
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(`${OLLAMA_URL}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: MODEL,
        prompt: buildPrompt(result),
        stream: false,
        think: false,
        options: { num_predict: 600 }
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      return { explanations: null, aiError: `Ollama returned an error (HTTP ${response.status}).` };
    }

    const data = await response.json();
    const text = (data.response || "").trim();

    if (!text) {
      return { explanations: null, aiError: "Gemma returned an empty response. Try again." };
    }

    return { explanations: text, aiError: null };
  } catch (err) {
    if (err.name === "AbortError") {
      return { explanations: null, aiError: "AI explanation timed out. The model may still be loading." };
    }
    return {
      explanations: null,
      aiError: "AI explanations are unavailable. Make sure Ollama is running on " + OLLAMA_URL + "."
    };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { explainFindings };