/**
 * Maps a 0–1 risk score to a colour token set.
 * Used by the gauge, stat cards, and table risk-score column.
 */
export function severityColor(score) {
  if (score >= 0.7) {
    return {
      hex: "#F2495C",
      tailwindText: "text-rose-400",
      tailwindBg: "bg-rose-500/20",
      tailwindBar: "bg-rose-500",
      label: "Critical",
    };
  }
  if (score >= 0.4) {
    return {
      hex: "#F2B84B",
      tailwindText: "text-amber-300",
      tailwindBg: "bg-amber-500/20",
      tailwindBar: "bg-amber-400",
      label: "Medium",
    };
  }
  return {
    hex: "#34D6C4",
    tailwindText: "text-teal-300",
    tailwindBg: "bg-teal-500/20",
    tailwindBar: "bg-teal-400",
    label: "Low",
  };
}

export function pct(val) {
  return `${Math.round(val * 100)}%`;
}
