import React from "react";

const BRAND_PLATFORMS = {
  google: { name: "Google", color: "text-blue-400", bg: "bg-blue-950/20", border: "border-blue-900/40" },
  microsoft: { name: "Microsoft", color: "text-cyan-400", bg: "bg-cyan-950/20", border: "border-cyan-900/40" },
  apple: { name: "Apple", color: "text-zinc-300", bg: "bg-zinc-950/30", border: "border-zinc-800" },
  amazon: { name: "Amazon", color: "text-yellow-400", bg: "bg-yellow-950/20", border: "border-yellow-900/40" },
  facebook: { name: "Facebook", color: "text-blue-500", bg: "bg-blue-950/20", border: "border-blue-900/40" },
  instagram: { name: "Instagram", color: "text-pink-400", bg: "bg-pink-950/20", border: "border-pink-900/40" },
  twitter: { name: "Twitter/X", color: "text-sky-400", bg: "bg-sky-950/20", border: "border-sky-900/40" },
  linkedin: { name: "LinkedIn", color: "text-blue-400", bg: "bg-blue-950/20", border: "border-blue-900/40" },
  paypal: { name: "PayPal", color: "text-blue-300", bg: "bg-blue-950/20", border: "border-blue-900/40" },
  netflix: { name: "Netflix", color: "text-red-500", bg: "bg-red-950/20", border: "border-red-900/40" },
  coinbase: { name: "Coinbase", color: "text-blue-400", bg: "bg-blue-950/20", border: "border-blue-900/40" },
  binance: { name: "Binance", color: "text-yellow-400", bg: "bg-yellow-950/20", border: "border-yellow-900/40" },
  github: { name: "GitHub", color: "text-gray-300", bg: "bg-gray-950/30", border: "border-gray-800" },
  sbi: { name: "SBI", color: "text-blue-300", bg: "bg-blue-950/20", border: "border-blue-900/40" },
  hdfc: { name: "HDFC", color: "text-red-400", bg: "bg-red-950/20", border: "border-red-900/40" },
  icici: { name: "ICICI", color: "text-orange-400", bg: "bg-orange-950/20", border: "border-orange-900/40" },
  phonepe: { name: "PhonePe", color: "text-purple-400", bg: "bg-purple-950/20", border: "border-purple-900/40" },
  paytm: { name: "Paytm", color: "text-blue-400", bg: "bg-blue-950/20", border: "border-blue-900/40" },
  flipkart: { name: "Flipkart", color: "text-yellow-400", bg: "bg-yellow-950/20", border: "border-yellow-900/40" },
};

export default function BrandImpersonation({ scannedData }) {
  if (!scannedData) {
    return (
      <div className="tmgc-card rounded-2xl p-6 text-center">
        <p className="text-sm text-zinc-500">Run a domain analysis to view brand impersonation results.</p>
      </div>
    );
  }

  const domain = scannedData.domain || "unknown";
  const findings = scannedData.findings || [];
  const brandFindings = findings.filter(
    (f) =>
      f.toUpperCase().includes("BRAND") ||
      f.toUpperCase().includes("IMPERSONAT") ||
      f.toUpperCase().includes("COMBO-SQUAT") ||
      f.toUpperCase().includes("TYPOSQUATTING") ||
      f.toUpperCase().includes("HOMOGLYPH") ||
      f.toUpperCase().includes("PHISHING")
  );

  // Extract brands from findings
  const detectedBrands = [];
  for (const [key, brand] of Object.entries(BRAND_PLATFORMS)) {
    const lower = brand.name.toLowerCase();
    if (domain.toLowerCase().includes(lower)) {
      detectedBrands.push(brand);
    }
  }

  const mlVerdict = scannedData.ml_result?.xgb_verdict || "N/A";
  const riskScore = scannedData.risk_score || 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <section className="tmgc-card rounded-2xl p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="tmgc-section-title-plain !mb-0 flex items-center gap-[10px]">
              BRAND IMPERSONATION ANALYSIS
            </h3>
            <p className="mt-2 text-sm text-zinc-500">
              Detecting brand impersonation, lookalike domains, and phishing campaigns for{" "}
              <strong className="text-green-400">{domain}</strong>
            </p>
          </div>
          <span
            className={`rounded-full border px-3 py-1 text-xs font-bold ${
              riskScore >= 50
                ? "border-red-500/40 bg-red-500/10 text-red-400"
                : riskScore >= 26
                ? "border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
                : "border-green-500/40 bg-green-500/10 text-green-400"
            }`}
          >
            Risk: {riskScore}/100
          </span>
        </div>
      </section>

      {/* Detected Brands */}
      {detectedBrands.length > 0 && (
        <section className="tmgc-card rounded-2xl p-6">
          <h3 className="tmgc-section-title-plain flex items-center gap-[10px]">DETECTED BRAND REFERENCES</h3>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {detectedBrands.map((brand, i) => (
              <div
                key={i}
                className={`rounded-lg border ${brand.border} ${brand.bg} p-4`}
              >
                <p className={`text-sm font-bold ${brand.color}`}>{brand.name}</p>
                <p className="mt-1 text-[10px] text-zinc-500">
                  Brand detected in domain analysis
                </p>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Brand Findings */}
      {brandFindings.length > 0 && (
        <section className="tmgc-card rounded-2xl p-6">
          <h3 className="tmgc-section-title-plain flex items-center gap-[10px]">IMPERSONATION FINDINGS</h3>
          <div className="mt-4 space-y-3">
            {brandFindings.map((finding, i) => {
              const isHighRisk =
                finding.toUpperCase().includes("HIGH RISK") ||
                finding.toUpperCase().includes("CRITICAL") ||
                finding.toUpperCase().includes("PHISHING");
              return (
                <div
                  key={i}
                  className={`rounded-lg border p-3 ${
                    isHighRisk
                      ? "border-red-500/30 bg-red-950/10"
                      : "border-yellow-500/30 bg-yellow-950/10"
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <span className={`mt-0.5 text-lg ${isHighRisk ? "text-red-400" : "text-yellow-400"}`}>
                      {isHighRisk ? "🚨" : "⚠️"}
                    </span>
                    <div>
                      <p
                        className={`text-xs font-bold ${
                          isHighRisk ? "text-red-400" : "text-yellow-300"
                        }`}
                      >
                        {isHighRisk ? "HIGH IMPACT" : "MEDIUM IMPACT"}
                      </p>
                      <p className="mt-1 text-sm text-zinc-400">{finding}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {brandFindings.length === 0 && detectedBrands.length === 0 && (
        <section className="tmgc-card rounded-2xl p-6 text-center">
          <div className="py-8">
            <span className="text-4xl">✅</span>
            <p className="mt-4 text-lg font-bold text-green-400">No Brand Impersonation Detected</p>
            <p className="mt-2 text-sm text-zinc-500">
              The analysis did not find any brand impersonation, lookalike patterns, or phishing indicators.
            </p>
          </div>
        </section>
      )}

      {/* ML Verdict */}
      <section className="tmgc-card rounded-2xl p-6">
        <h3 className="tmgc-section-title-plain flex items-center gap-[10px]">MACHINE LEARNING VERDICT</h3>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div className="rounded-lg border border-green-950/40 bg-black/30 p-4">
            <p className="text-[10px] font-bold tracking-wider text-zinc-500">ML VERDICT</p>
            <p
              className={`mt-1 text-lg font-bold ${
                mlVerdict === "phishing"
                  ? "text-red-400"
                  : mlVerdict === "suspicious"
                  ? "text-yellow-400"
                  : "text-green-400"
              }`}
            >
              {mlVerdict.toUpperCase()}
            </p>
          </div>
          <div className="rounded-lg border border-green-950/40 bg-black/30 p-4">
            <p className="text-[10px] font-bold tracking-wider text-zinc-500">ML SCORE</p>
            <p className="mt-1 text-lg font-bold text-cyan-400">
              {scannedData.ml_result?.xgb_score ?? "N/A"}
            </p>
          </div>
        </div>
      </section>

      {/* Recommended Actions */}
      <section className="tmgc-card rounded-2xl p-6">
        <h3 className="tmgc-section-title-plain flex items-center gap-[10px]">RECOMMENDED ACTIONS</h3>
        <div className="mt-4 space-y-3">
          {riskScore >= 50 && (
            <div className="rounded-lg border border-red-500/30 bg-red-950/10 p-3">
              <p className="text-sm font-bold text-red-400">🚨 Immediate Review Required</p>
              <p className="mt-1 text-xs text-red-300/70">
                This domain shows significant brand impersonation signals. Do not enter credentials or personal information.
              </p>
            </div>
          )}
          {riskScore >= 26 && riskScore < 50 && (
            <div className="rounded-lg border border-yellow-500/30 bg-yellow-950/10 p-3">
              <p className="text-sm font-bold text-yellow-400">⚠️ Manual Verification Recommended</p>
              <p className="mt-1 text-xs text-yellow-300/70">
                Some suspicious brand-related patterns were detected. Verify the domain's authenticity before trusting it.
              </p>
            </div>
          )}
          {riskScore < 26 && (
            <div className="rounded-lg border border-green-500/30 bg-green-500/10 p-3">
              <p className="text-sm font-bold text-green-400">✅ No Action Required</p>
              <p className="mt-1 text-xs text-green-300/70">
                No brand impersonation signals detected. The domain appears legitimate.
              </p>
            </div>
          )}
          <div className="rounded-lg border border-green-950/40 bg-black/30 p-3">
            <p className="text-xs font-bold text-green-600">ADDITIONAL CHECKS</p>
            <ul className="mt-2 space-y-1 text-xs text-zinc-500">
              <li>• Verify domain registration date and registrar</li>
              <li>• Check SSL certificate issuer and validity</li>
              <li>• Review WHOIS privacy/redaction status</li>
              <li>• Cross-reference with known brand domains</li>
              <li>• Check external threat intelligence feeds</li>
            </ul>
          </div>
        </div>
      </section>
    </div>
  );
}
