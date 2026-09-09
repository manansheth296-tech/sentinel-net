import { TrendingUp, Target, AlertTriangle, Zap } from "lucide-react";
import StatCard from "./StatCard";
import StageBadge from "./StageBadge";
import { severityColor } from "../lib/severity";
import { getStageColor } from "../lib/stageColors";

export default function SessionOverview({ data }) {
  const { infiltration_timeline, predicted_stage, stage_probs, top_features, flagged_flows } = data;

  const peakProb = Math.max(...infiltration_timeline.map((t) => t.probability));
  const peakColor = severityColor(peakProb);
  const timelineChart = infiltration_timeline.map((t) => ({ value: t.probability }));

  const stageColor = getStageColor(predicted_stage);
  const stageChart = Object.entries(stage_probs).map(([k, v]) => ({ name: k, value: v }));

  const flowsChart = flagged_flows.map((f) => ({ value: f.risk_score }));

  const topFeature = top_features[0];
  const featuresChart = top_features.map((f) => ({ value: f.importance, name: f.feature }));

  return (
    <section aria-labelledby="session-overview-heading">
      <div className="mb-3">
        <h2
          id="session-overview-heading"
          className="text-xs font-semibold uppercase tracking-widest text-muted"
        >
          Session Overview
        </h2>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={<TrendingUp className="h-4 w-4" />}
          iconBg={peakColor.tailwindBg}
          iconColor={peakColor.tailwindText}
          headline={`${Math.round(peakProb * 100)}%`}
          label="Peak attack probability"
          chartData={timelineChart}
          barColor={peakColor.hex}
        />
        <StatCard
          icon={<Target className="h-4 w-4" />}
          iconBg={stageColor.bg}
          iconColor={stageColor.text}
          headline={predicted_stage}
          label="Predicted MITRE stage"
          badge={<StageBadge stage={predicted_stage} />}
          chartData={stageChart}
          barColor={stageColor.hex}
        />
        <StatCard
          icon={<AlertTriangle className="h-4 w-4" />}
          iconBg="bg-rose-500/20"
          iconColor="text-rose-400"
          headline={String(flagged_flows.length)}
          label="Active flagged flows"
          chartData={flowsChart}
          barColor="#F2495C"
        />
        <StatCard
          icon={<Zap className="h-4 w-4" />}
          iconBg="bg-violet-500/20"
          iconColor="text-violet-400"
          headline={`${Math.round(topFeature.importance * 100)}%`}
          label={topFeature.feature}
          chartData={featuresChart}
          barColor="#8B5CF6"
        />
      </div>
    </section>
  );
}
