import { BarChart, Bar, ResponsiveContainer, Tooltip as ReTooltip, Cell } from "recharts";

export default function StatCard({
  icon,
  iconBg = "bg-violet-500/20",
  iconColor = "text-violet-400",
  headline,
  label,
  badge,
  chartData,
  barColor = "#8B5CF6",
}) {
  return (
    <div
      className="flex flex-col rounded-2xl border p-5 gap-3 transition-colors"
      style={{ backgroundColor: "var(--panel)", borderColor: "var(--border)" }}
    >
      <div className="flex items-start justify-between">
        <div className={`flex h-9 w-9 items-center justify-center rounded-xl ${iconBg} border border-white/5`}>
          <span className={iconColor}>{icon}</span>
        </div>
      </div>

      <div>
        <p className="font-mono text-2xl font-bold text-primary leading-none tracking-tight">
          {headline}
        </p>
        {badge && <div className="mt-1.5">{badge}</div>}
        <p className="mt-1 text-xs text-muted">{label}</p>
      </div>

      {chartData && chartData.length > 0 && (
        <div className="h-10 w-full mt-auto">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} barCategoryGap="20%">
              <ReTooltip
                cursor={false}
                contentStyle={{
                  background: "var(--panel)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  fontSize: 11,
                  color: "var(--text)",
                }}
                formatter={(v) =>
                  typeof v === "number" && v <= 1 ? `${Math.round(v * 100)}%` : v
                }
              />
              <Bar dataKey="value" radius={[2, 2, 0, 0]}>
                {chartData.map((_, i) => (
                  <Cell
                    key={i}
                    fill={barColor}
                    fillOpacity={0.5 + (i / chartData.length) * 0.5}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
