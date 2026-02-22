import Link from "next/link";

type WarningPageProps = {
  searchParams: {
    url?: string;
    score?: string;
    label?: string;
    reason?: string;
  };
};

function safeExternalUrl(url: string): string {
  const candidate = url.trim();
  if (!candidate) {
    return "";
  }

  const normalized = /^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`;

  try {
    const parsed = new URL(normalized);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    if (!parsed.hostname) {
      return "";
    }
    return parsed.toString();
  } catch {
    return "";
  }
}

export default function WarningPage({ searchParams }: WarningPageProps) {
  const url = searchParams.url || "";
  const score = searchParams.score || "0";
  const label = searchParams.label || "Suspicious";
  const reason = searchParams.reason || "Potential risk indicators were detected.";
  const openHref = url ? safeExternalUrl(url) : "";

  return (
    <main className="page">
      <section className="panel danger-border">
        <p className="eyebrow">Warning Gate</p>
        <h1>Review Before Opening URL</h1>
        <p className="muted">
          Threat label: <strong>{label}</strong> | Score: <strong>{score}</strong>/100
        </p>
        <p>{reason}</p>
        <p>
          Target URL: <code>{url || "N/A"}</code>
        </p>

        <div className="warning-actions">
          <Link href="/" className="btn-secondary">
            Go Back
          </Link>
          {openHref ? (
            <a className="btn-primary" href={openHref} target="_blank" rel="noopener noreferrer">
              Open Anyway
            </a>
          ) : (
            <button className="btn-primary" disabled>
              Open Anyway
            </button>
          )}
        </div>
      </section>
    </main>
  );
}
