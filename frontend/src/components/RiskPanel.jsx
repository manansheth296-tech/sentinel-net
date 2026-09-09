import { MoreHorizontal } from "lucide-react";
import RiskGauge from "./RiskGauge";
import BenchmarkRow from "./BenchmarkRow";

export default function RiskPanel({ data }) {
  const { infiltration_timeline, benchmark } = data;
  const latestProb = infiltration_timeline[infiltration_timeline.length - 1]?.probability ?? 0;
  const score = Math.round(latestProb * 100);

  return (
    <section
      aria-labelledby="risk-panel-heading"
      className="rounded-2xl border p-5 flex flex-col transition-colors"
      style={{ backgroundColor: "var(--panel)", borderColor: "var(--border)" }}
    >
      <div className="flex items-center justify-between mb-4">
        <h2 id="risk-panel-heading" className="text-sm font-semibold text-primary">
          Attack Risk Score
        </h2>
        <button type="button" aria-label="More options" className="text-muted hover:text-primary transition-colors">
          <MoreHorizontal className="h-4 w-4" />
        </button>
      </div>
      <div className="flex flex-col items-center flex-1 justify-center">
        <RiskGauge score={score} />
      </div>
      <BenchmarkRow benchmark={benchmark} />
    </section>
  );
}
