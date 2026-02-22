import { RiskExplanationData } from "@/types/qrshield";

type Props = {
  explanation: RiskExplanationData | null | undefined;
};

export default function ThreatExplanationPanel({ explanation }: Props) {
  if (!explanation) {
    return (
      <section className="panel">
        <h2>Threat Explanation</h2>
        <p className="muted">No explanation returned yet.</p>
      </section>
    );
  }

  return (
    <section className="panel">
      <h2>Threat Explanation</h2>
      <p>{explanation.explanation}</p>
      <h3>Top Contributing Features</h3>
      <ul className="contributor-list">
        {explanation.top_contributors.slice(0, 3).map((item) => (
          <li key={`${item.source}:${item.feature}:${item.detail}`}>
            <strong>{item.feature}</strong> ({item.source}) - {item.detail}
          </li>
        ))}
      </ul>
    </section>
  );
}

