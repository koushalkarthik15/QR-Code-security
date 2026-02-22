import { ThreatLabel } from "@/types/qrshield";

type Props = {
  score: number;
  label: ThreatLabel;
};

function labelClass(label: ThreatLabel): string {
  if (label === "Malicious") {
    return "tone-danger";
  }
  if (label === "Suspicious") {
    return "tone-warn";
  }
  return "tone-safe";
}

export default function RiskScoreDisplay({ score, label }: Props) {
  const bounded = Math.max(0, Math.min(100, score));
  return (
    <section className="panel">
      <div className="panel-title-row">
        <h2>Risk Score</h2>
        <span className={`pill ${labelClass(label)}`}>{label}</span>
      </div>
      <p className="score-value">{bounded.toFixed(2)} / 100</p>
      <div className="progress-track" aria-label="Risk score bar">
        <div className={`progress-fill ${labelClass(label)}`} style={{ width: `${bounded}%` }} />
      </div>
    </section>
  );
}

