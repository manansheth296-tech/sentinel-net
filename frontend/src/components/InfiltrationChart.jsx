import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, ReferenceLine,
} from "recharts";

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload?.length) {
    return (
      <div
        className="rounded-lg border p-2.5 text-xs"
        style={{ background: "var(--panel)", borderColor: "var(--border)", color: "var(--text)" }}
      >
        <p className="font-mono text-muted">{label}</p>
        <p className="font-mono text-violet-400 font-semibold">
          {Math.round(payload[0].value * 100)}% risk
        </p>
      </div>
    );
  }
  return null;
};

export default function InfiltrationChart({ timeline }) {
  const data = timeline.map((t) => ({ time: t.window_start, prob: t.probability }));

  return (
    <section
      aria-labelledby="infiltration-heading"
      className="rounded-2xl border p-5 transition-colors"
      style={{ backgroundColor: "var(--panel)", borderColor: "var(--border)" }}
    >
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 id="infiltration-heading" className="text-sm font-semibold text-primary">
            Infiltration Timeline
          </h2>
          <p className="text-xs text-muted">Attack probability over time windows</p>
        </div>
        <span className="font-mono text-xs text-violet-400 bg-violet-500/10 border border-violet-500/20 rounded-md px-2 py-1">
          {data.length} windows
        </span>
      </div>

      <div className="h-44">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <defs>
              <linearGradient id="probGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#8B5CF6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#8B5CF6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
            <XAxis
              dataKey="time"
              tick={{ fill: "var(--muted)", fontSize: 10, fontFamily: "monospace" }}
              tickLine={false} axisLine={false}
            />
            <YAxis
              domain={[0, 1]}
              tickFormatter={(v) => `${Math.round(v * 100)}%`}
              tick={{ fill: "var(--muted)", fontSize: 10 }}
              tickLine={false} axisLine={false}
            />
            <Tooltip content={<CustomTooltip />} />
            <ReferenceLine y={0.5} stroke="#F2B84B" strokeDasharray="4 4" strokeWidth={1}
              label={{ value: "50%", fill: "#F2B84B", fontSize: 9, position: "right" }} />
            <ReferenceLine y={0.7} stroke="#F2495C" strokeDasharray="4 4" strokeWidth={1}
              label={{ value: "70%", fill: "#F2495C", fontSize: 9, position: "right" }} />
            <Area
              type="monotone" dataKey="prob"
              stroke="#8B5CF6" strokeWidth={2}
              fill="url(#probGrad)"
              dot={{ fill: "#8B5CF6", r: 3, strokeWidth: 0 }}
              activeDot={{ r: 5, fill: "#A78BFA" }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
