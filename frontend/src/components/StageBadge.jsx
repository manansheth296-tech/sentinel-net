import { getStageColor } from "../lib/stageColors";

export default function StageBadge({ stage, size = "sm" }) {
  const c = getStageColor(stage);
  const sizeClass = size === "lg" ? "text-sm px-3 py-1" : "text-xs px-2 py-0.5";
  return (
    <span
      className={`inline-flex items-center rounded-full font-medium border ${c.bg} ${c.text} ${c.border} ${sizeClass}`}
    >
      <span
        className="mr-1.5 h-1.5 w-1.5 rounded-full"
        style={{ backgroundColor: c.hex }}
      />
      {stage}
    </span>
  );
}
