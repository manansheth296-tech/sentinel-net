import { useApp } from "../context/AppContext";
import { severityColor } from "../lib/severity";

const TOTAL_SEGMENTS = 30;
const SWEEP_DEG = 180;
const GAP_DEG = 3;

export default function RiskGauge({ score }) {
  const { state } = useApp();
  const isDark = state.theme === "dark";

  const clampedScore = Math.min(100, Math.max(0, score));
  const litCount = Math.round((clampedScore / 100) * TOTAL_SEGMENTS);
  const color = severityColor(clampedScore / 100);

  // Dim segment color adapts to theme
  const dimFill = isDark ? "#1E2540" : "#DDE1EF";
  const labelFill = isDark ? "#8A93B3" : "#6B7280";
  const textFill = isDark ? "#E9ECF6" : "#12131A";

  const segments = [];
  const segSpan = (SWEEP_DEG - GAP_DEG * (TOTAL_SEGMENTS - 1)) / TOTAL_SEGMENTS;
  const toRad = (deg) => (deg * Math.PI) / 180;
  const cx = 110, cy = 100, rOuter = 84, rInner = 68;

  for (let i = 0; i < TOTAL_SEGMENTS; i++) {
    const startAngle = 180 - i * (segSpan + GAP_DEG);
    const endAngle = startAngle - segSpan;
    const lit = i < litCount;

    const ox1 = cx + rOuter * Math.cos(toRad(startAngle));
    const oy1 = cy - rOuter * Math.sin(toRad(startAngle));
    const ox2 = cx + rOuter * Math.cos(toRad(endAngle));
    const oy2 = cy - rOuter * Math.sin(toRad(endAngle));
    const ix1 = cx + rInner * Math.cos(toRad(startAngle));
    const iy1 = cy - rInner * Math.sin(toRad(startAngle));
    const ix2 = cx + rInner * Math.cos(toRad(endAngle));
    const iy2 = cy - rInner * Math.sin(toRad(endAngle));

    const d = [
      `M ${ox1} ${oy1}`,
      `A ${rOuter} ${rOuter} 0 0 1 ${ox2} ${oy2}`,
      `L ${ix2} ${iy2}`,
      `A ${rInner} ${rInner} 0 0 0 ${ix1} ${iy1}`,
      "Z",
    ].join(" ");

    segments.push(
      <path
        key={i}
        d={d}
        fill={lit ? color.hex : dimFill}
        opacity={lit ? 1 : 0.6}
        style={{
          filter: lit ? `drop-shadow(0 0 3px ${color.hex}55)` : "none",
          transition: "fill 0.35s ease",
        }}
      />
    );
  }

  return (
    <div className="flex flex-col items-center">
      <svg
        viewBox="20 10 180 110"
        className="w-56 select-none"
        aria-label={`Risk score: ${clampedScore}`}
        role="img"
      >
        {segments}
        <text
          x="110" y="88"
          textAnchor="middle"
          fontFamily="'JetBrains Mono', monospace"
          fill={labelFill}
          fontSize="9"
        >
          Score
        </text>
        <text
          x="110" y="104"
          textAnchor="middle"
          fontFamily="'JetBrains Mono', monospace"
          fill={color.hex}
          fontSize="22"
          fontWeight="700"
        >
          {clampedScore}
        </text>
        <text x="24" y="104" fill={labelFill} fontSize="8" textAnchor="middle">0</text>
        <text x="196" y="104" fill={labelFill} fontSize="8" textAnchor="middle">100</text>
      </svg>

      <span
        className="mt-1 font-mono text-xs font-semibold tracking-widest uppercase"
        style={{ color: color.hex }}
      >
        {color.label} Risk
      </span>
    </div>
  );
}
