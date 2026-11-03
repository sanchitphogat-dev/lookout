const SEVERITY_WEIGHTS = {
  critical: 35,
  high: 25,
  medium: 15,
  low: 5,
};

function calculateRisk(findings) {
  if (!findings || findings.length === 0) {
    return {
      score: 0,
      level: "low",
      explanation: "No suspicious indicators found. The target appears safe.",
      recommendation: "No action required.",
    };
  }

  let rawScore = 0;
  for (const finding of findings) {
    rawScore += SEVERITY_WEIGHTS[finding.severity] || 5;
  }

  const score = Math.min(100, Math.round(rawScore));

  let level;
  if (score >= 60) {
    level = "high";
  } else if (score >= 30) {
    level = "medium";
  } else {
    level = "low";
  }

  const criticalFindings = findings.filter((f) => f.severity === "critical");
  const highFindings = findings.filter((f) => f.severity === "high");
  const mediumFindings = findings.filter((f) => f.severity === "medium");

  let explanation = `${findings.length} indicator(s) detected.`;
  if (criticalFindings.length > 0) {
    explanation += ` ${criticalFindings.length} CRITICAL finding(s) including: ${criticalFindings[0].detail}.`;
  }
  if (highFindings.length > 0) {
    explanation += ` ${highFindings.length} high-severity finding(s) including: ${highFindings[0].detail}.`;
  }
  if (mediumFindings.length > 0) {
    explanation += ` ${mediumFindings.length} medium-severity finding(s).`;
  }

  let recommendation;
  if (level === "high") {
    recommendation =
      "HIGH RISK — Do not open or execute this target. Immediately quarantine and investigate. Report to your security team.";
  } else if (level === "medium") {
    recommendation =
      "MODERATE RISK — Exercise caution. Review findings manually before proceeding. Consider scanning with additional tools.";
  } else {
    recommendation =
      "LOW RISK — Target appears relatively safe, but always stay vigilant. Monitor for any unusual behavior.";
  }

  return { score, level, explanation, recommendation };
}

module.exports = { calculateRisk };
