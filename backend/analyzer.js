// Parses raw header text like:
//   content-security-policy: default-src 'self'
//   strict-transport-security: max-age=31536000
// into a Map of lowercase header name -> value.
// Repeated headers (such as Set-Cookie) are stored as arrays.
function parseHeaders(text) {
  const headers = new Map();
  const lines = text.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === "" || !trimmed.includes(":")) continue;

    const index = trimmed.indexOf(":");
    const name = trimmed.slice(0, index).trim().toLowerCase();
    const value = trimmed.slice(index + 1).trim();

    if (!name) continue;

    if (name === "set-cookie") {
      const existing = headers.get(name) || [];
      existing.push(value);
      headers.set(name, existing);
    } else {
      headers.set(name, value);
    }
  }

  return headers;
}

// Each rule describes one security header and how to judge it.
// "weight" is how many points the header is worth in the score.
// "impact" is a fixed risk weight (1 to 10) used only for ranking.
const RULES = [
  {
    header: "Content-Security-Policy",
    key: "content-security-policy",
    weight: 25,
    severity: "high",
    impact: 9,
    check(value) {
      if (value.includes("unsafe-inline") || value.includes("unsafe-eval")) {
        return { status: "weak", message: "CSP allows 'unsafe-inline' or 'unsafe-eval', which weakens XSS protection." };
      }
      if (!value.includes("default-src") && !value.includes("script-src")) {
        return { status: "weak", message: "CSP has no default-src or script-src directive." };
      }
      return { status: "ok", message: "CSP is present and does not use unsafe directives." };
    }
  },
  {
    header: "Strict-Transport-Security",
    key: "strict-transport-security",
    weight: 20,
    severity: "high",
    impact: 8,
    check(value) {
      const match = value.match(/max-age=(\d+)/i);
      if (!match) {
        return { status: "weak", message: "HSTS is present but has no valid max-age value." };
      }
      if (parseInt(match[1], 10) < 15552000) {
        return { status: "weak", message: "HSTS max-age is under six months (15552000 seconds)." };
      }
      return { status: "ok", message: "HSTS is set with a strong max-age." };
    }
  },
  {
    header: "X-Content-Type-Options",
    key: "x-content-type-options",
    weight: 15,
    severity: "medium",
    impact: 6,
    check(value) {
      if (value.toLowerCase() !== "nosniff") {
        return { status: "weak", message: "X-Content-Type-Options should be set to 'nosniff'." };
      }
      return { status: "ok", message: "MIME-type sniffing is disabled." };
    }
  },
  {
    header: "Referrer-Policy",
    key: "referrer-policy",
    weight: 15,
    severity: "low",
    impact: 3,
    check(value) {
      const unsafe = ["unsafe-url", "no-referrer-when-downgrade"];
      if (unsafe.includes(value.toLowerCase())) {
        return { status: "weak", message: `Referrer-Policy '${value}' can leak full URLs to other sites.` };
      }
      return { status: "ok", message: "Referrer-Policy limits referrer information." };
    }
  },
  {
    header: "X-Frame-Options / frame-ancestors",
    key: "x-frame-options",
    weight: 25,
    severity: "medium",
    impact: 7,
    check(value, headers) {
      const csp = headers.get("content-security-policy") || "";
      if (csp.includes("frame-ancestors")) {
        return { status: "ok", message: "CSP frame-ancestors controls framing." };
      }
      if (value) {
        const v = value.toUpperCase();
        if (v === "DENY" || v === "SAMEORIGIN") {
          return { status: "ok", message: "X-Frame-Options prevents clickjacking." };
        }
        return { status: "weak", message: "X-Frame-Options has an unrecognized value." };
      }
      return { status: "missing", message: "No clickjacking protection found (no X-Frame-Options or CSP frame-ancestors)." };
    }
  }
];

// Extra checks that do not change the score.
// They add findings for cookies and software version disclosure.
const EXTRA_CHECKS = [
  {
    header: "Set-Cookie",
    severity: "medium",
    impact: 7,
    run(headers) {
      const cookies = headers.get("set-cookie");
      if (!cookies) return [];

      const findings = [];
      cookies.forEach((cookie) => {
        const name = cookie.split("=")[0].trim() || "unnamed";
        const flags = cookie.toLowerCase();
        const problems = [];

        if (!flags.includes("secure")) problems.push("Secure");
        if (!flags.includes("httponly")) problems.push("HttpOnly");
        if (!flags.includes("samesite")) problems.push("SameSite");

        if (problems.length > 0) {
          findings.push({
            header: "Set-Cookie",
            status: "weak",
            severity: "medium",
            impact: 7,
            message: `Cookie '${name}' is missing the ${problems.join(", ")} flag${problems.length > 1 ? "s" : ""}.`
          });
        }
      });
      return findings;
    }
  },
  {
    header: "Server / X-Powered-By",
    severity: "low",
    impact: 2,
    run(headers) {
      const findings = [];
      for (const key of ["server", "x-powered-by"]) {
        const value = headers.get(key);
        // A version number such as "Apache/2.4.41" or "PHP/7.4.3" reveals software details
        if (typeof value === "string" && /\d+\.\d+/.test(value)) {
          findings.push({
            header: key === "server" ? "Server" : "X-Powered-By",
            status: "weak",
            severity: "low",
            impact: 2,
            message: `The ${key} header reveals software version information ('${value}'). Remove or hide it.`
          });
        }
      }
      return findings;
    }
  }
];

// Severity gives a base value, and impact adds the header-specific risk.
// Status scales it: "missing" is worse than "weak".
const SEVERITY_BASE = { high: 30, medium: 20, low: 10 };
const STATUS_MULTIPLIER = { missing: 1.0, weak: 0.7 };

function riskScore(finding) {
  const base = SEVERITY_BASE[finding.severity] || 10;
  const statusFactor = STATUS_MULTIPLIER[finding.status] || 0.7;
  return Math.round((base + finding.impact * 3) * statusFactor);
}

// Adds riskScore and priority to each finding, sorted highest risk first.
// Priority 1 is the most urgent. The security score is not affected.
function rankFindings(findings) {
  const ranked = findings
    .map((f) => ({ ...f, riskScore: riskScore(f) }))
    .sort((a, b) => b.riskScore - a.riskScore);

  return ranked.map((f, i) => ({ ...f, priority: i + 1 }));
}

// Main entry point. Takes raw header text, returns the analysis.
function analyzeHeaders(text) {
  const headers = parseHeaders(text);
  const findings = [];
  let earned = 0;
  let total = 0;

  for (const rule of RULES) {
    const value = headers.get(rule.key);
    total += rule.weight;

    let result;
    if (value === undefined) {
      // X-Frame-Options is "missing" only if CSP frame-ancestors is also absent
      result = rule.key === "x-frame-options"
        ? rule.check(undefined, headers)
        : { status: "missing", message: `${rule.header} header is missing.` };
    } else {
      result = rule.check(value, headers);
    }

    // Full points for "ok", half for "weak", zero for "missing"
    if (result.status === "ok") earned += rule.weight;
    else if (result.status === "weak") earned += rule.weight / 2;

    // Only report problems, not healthy headers
    if (result.status !== "ok") {
      findings.push({
        header: rule.header,
        status: result.status,
        severity: rule.severity,
        impact: rule.impact,
        message: result.message
      });
    }
  }

  // Extra checks add findings but do not affect the score
  for (const check of EXTRA_CHECKS) {
    findings.push(...check.run(headers));
  }

  return {
    score: Math.round((earned / total) * 100),
    scoreNote: "Estimate based on header checks only",
    findings: rankFindings(findings)
  };
}

module.exports = { analyzeHeaders, parseHeaders };