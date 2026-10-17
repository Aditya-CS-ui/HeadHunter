// Built-in sample header sets for demos and testing.
// Nitin's frontend loads these through GET /api/samples.
const SAMPLES = [
  {
    id: "weak",
    title: "Weak configuration (before)",
    description: "Missing or misconfigured security headers.",
    headers: [
      "server: Apache/2.4.41",
      "content-type: text/html; charset=UTF-8",
      "content-security-policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "strict-transport-security: max-age=3600",
      "referrer-policy: unsafe-url",
      "x-powered-by: PHP/7.4.3"
    ].join("\n")
  },
  {
    id: "hardened",
    title: "Hardened configuration (after)",
    description: "Same site with the security headers corrected.",
    headers: [
      "server: Apache/2.4.41",
      "content-type: text/html; charset=UTF-8",
      "content-security-policy: default-src 'self'; frame-ancestors 'none'",
      "strict-transport-security: max-age=31536000; includeSubDomains",
      "x-content-type-options: nosniff",
      "referrer-policy: strict-origin-when-cross-origin",
      "x-frame-options: DENY"
    ].join("\n")
  }
];

function getSamples() {
  return SAMPLES;
}

module.exports = { getSamples };