import { Activity, ArrowLeft } from "lucide-react";
import InfiltrationChart from "../components/InfiltrationChart";
import RiskPanel from "../components/RiskPanel";
import FlaggedFlowsTable from "../components/FlaggedFlowsTable";
import { useApp } from "../context/AppContext";

export default function LiveAnalysisView() {
  const { state, dispatch } = useApp();

  if (!state.currentResult) {
    return (
      <div className="flex min-h-[calc(100vh-8rem)] flex-col items-center justify-center gap-4">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-violet-600/10 border border-violet-500/20">
          <Activity className="h-7 w-7 text-violet-400/40" />
        </div>
        <p className="text-sm font-semibold text-primary">No analysis data yet</p>
        <p className="text-xs text-muted">Run an analysis from the Dashboard first</p>
        <button
          onClick={() => dispatch({ type: "SET_VIEW", payload: "dashboard" })}
          className="mt-2 flex items-center gap-1.5 rounded-lg border px-4 py-2 text-sm text-muted hover:border-violet-500/50 hover:text-primary transition-colors"
          style={{ borderColor: "var(--border)" }}
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Go to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1fr_320px]">
        <InfiltrationChart timeline={state.currentResult.infiltration_timeline} />
        <RiskPanel data={state.currentResult} />
      </div>
      <FlaggedFlowsTable data={state.currentResult} />
    </div>
  );
}
