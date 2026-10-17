const express = require("express");
const path = require("path");
const { analyzeHeaders } = require("./analyzer");
const { getSamples } = require("./samples");
const { explainFindings } = require("./ollama");

const app = express();
const PORT = process.env.PORT || 3000;

// Parse JSON request bodies
app.use(express.json({ limit: "100kb" }));

// Serve Nitin's frontend (index.html, css/, js/, assets/)
app.use(express.static(path.join(__dirname, "../frontend/headerhunter-frontend")));

// GET /api/samples: returns built-in sample header sets
app.get("/api/samples", (req, res) => {
  res.json(getSamples());
});

// POST /api/analyze: runs the security checks, then asks Gemma for explanations
app.post("/api/analyze", async (req, res) => {
  const headerText = req.body && req.body.headers;

  if (typeof headerText !== "string" || headerText.trim() === "") {
    return res.status(400).json({
      error: "Request body must include a non-empty 'headers' string."
    });
  }

  try {
    const result = analyzeHeaders(headerText);
    const ai = await explainFindings(result);
    res.json({
      score: result.score,
      scoreNote: result.scoreNote,
      findings: result.findings,
      explanations: ai.explanations,
      aiError: ai.aiError
    });
  } catch (err) {
    console.error("Analyze error:", err);
    res.status(500).json({ error: "Internal server error during analysis." });
  }
});

app.listen(PORT, () => {
  console.log(`HeaderHunter running at http://localhost:${PORT}`);
});