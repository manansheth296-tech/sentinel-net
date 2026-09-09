export default function BenchmarkRow({ benchmark }) {
  const { world_model, logistic_baseline } = benchmark;
  const metrics = [
    { key: "f1",        label: "F1" },
    { key: "precision", label: "Prec" },
    { key: "recall",    label: "Recall" },
    { key: "fpr",       label: "FPR", lower_better: true },
  ];

  return (
    <div
      className="mt-5 rounded-xl p-4 border"
      style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--border)" }}
    >
      <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted">
        Model Benchmark
      </p>

      <div className="grid grid-cols-2 gap-2 mb-3">
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-violet-500 inline-block" />
          <span className="text-xs text-primary font-medium">World Model V4</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-violet-300/30 inline-block" />
          <span className="text-xs text-muted">Logistic Baseline</span>
        </div>
      </div>

      <div className="space-y-2">
        {metrics.map(({ key, label, lower_better }) => {
          const wv = world_model[key];
          const bv = logistic_baseline[key];
          const worldBetter = lower_better ? wv < bv : wv > bv;
          return (
            <div key={key} className="flex items-center gap-3">
              <span className="w-10 text-xs text-muted shrink-0">{label}</span>
              {/* World model */}
              <div className="flex flex-1 items-center gap-1.5">
                <div
                  className="flex-1 h-1.5 rounded-full overflow-hidden"
                  style={{ backgroundColor: "var(--border)" }}
                >
                  <div
                    className="h-full rounded-full bg-violet-500 transition-all duration-700"
                    style={{ width: `${Math.min(wv * 100, 100)}%` }}
                  />
                </div>
                <span className={`font-mono text-xs w-10 text-right ${worldBetter ? "text-violet-400" : "text-muted"}`}>
                  {(wv * 100).toFixed(1)}<span className="text-muted text-[10px]">%</span>
                </span>
              </div>
              {/* Baseline */}
              <div className="flex flex-1 items-center gap-1.5">
                <div
                  className="flex-1 h-1.5 rounded-full overflow-hidden"
                  style={{ backgroundColor: "var(--border)" }}
                >
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${Math.min(bv * 100, 100)}%`, backgroundColor: "var(--muted)", opacity: 0.4 }}
                  />
                </div>
                <span className="font-mono text-xs text-muted w-10 text-right">
                  {(bv * 100).toFixed(1)}<span className="text-[10px]">%</span>
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
