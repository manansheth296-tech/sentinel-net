/**
 * MITRE-stage palette — matches the design spec exactly.
 * Each entry has: bg (chip/badge background), text (label), bar (progress/arc fill).
 */
export const STAGE_COLORS = {
  "Normal Traffic": {
    bg: "bg-teal-500/20",
    text: "text-teal-300",
    border: "border-teal-500/40",
    hex: "#34D6C4",
  },
  Reconnaissance: {
    bg: "bg-teal-400/20",
    text: "text-teal-200",
    border: "border-teal-400/40",
    hex: "#7FE0D2",
  },
  "Initial Access": {
    bg: "bg-amber-500/20",
    text: "text-amber-300",
    border: "border-amber-500/40",
    hex: "#F2B84B",
  },
  "Lateral Movement": {
    bg: "bg-orange-500/20",
    text: "text-orange-300",
    border: "border-orange-500/40",
    hex: "#F08A3C",
  },
  "Command & Control": {
    bg: "bg-red-500/20",
    text: "text-red-400",
    border: "border-red-500/40",
    hex: "#F26B4C",
  },
  Impact: {
    bg: "bg-rose-500/20",
    text: "text-rose-400",
    border: "border-rose-500/40",
    hex: "#F2495C",
  },
};

export function getStageColor(stage) {
  return STAGE_COLORS[stage] ?? STAGE_COLORS["Normal Traffic"];
}
