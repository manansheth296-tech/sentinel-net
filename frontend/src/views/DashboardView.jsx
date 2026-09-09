import { ArrowRight } from "lucide-react";
import UploadPanel from "../components/UploadPanel";
import SessionOverview from "../components/SessionOverview";
import ErrorPanel from "../components/ErrorPanel";
import { useApp } from "../context/AppContext";
import { useToast } from "../context/ToastContext";
import { analyzeFile, loadMock } from "../api/analyze";

export default function DashboardView() {
  const { state, dispatch } = useApp();
  const { addToast } = useToast();
  const { appState, currentResult, error, sourceLabel, notifyBrowserEnabled } = state;

  function fireNotification(data) {
    const peak = Math.max(...data.infiltration_timeline.map((t) => t.probability));
    if (peak >= 0.7) {
      addToast({
        type: "critical",
        message: `⚠ Critical risk — ${Math.round(peak * 100)}% attack probability · Stage: ${data.predicted_stage}`,
        duration: 10000,
      });
      if (notifyBrowserEnabled && document.hidden && Notification.permission === "granted") {
        new Notification("SentinelNet — Critical Risk", {
          body: `${Math.round(peak * 100)}% probability · Stage: ${data.predicted_stage}`,
          icon: "/favicon.svg",
        });
      }
    }
  }

  async function handleUpload(file) {
    dispatch({ type: "ANALYSIS_START", payload: file.name });
    try {
      const data = await analyzeFile(file);
      dispatch({ type: "ANALYSIS_SUCCESS", payload: { result: data, sourceLabel: file.name } });
      fireNotification(data);
    } catch (err) {
      dispatch({ type: "ANALYSIS_ERROR", payload: err.message });
    }
  }

  async function handleLoadMock() {
    dispatch({ type: "ANALYSIS_START", payload: "sample-attack-session.csv" });
    try {
      const data = await loadMock();
      dispatch({ type: "ANALYSIS_SUCCESS", payload: { result: data, sourceLabel: "sample-attack-session.csv" } });
      fireNotification(data);
    } catch (err) {
      dispatch({ type: "ANALYSIS_ERROR", payload: err.message });
    }
  }

  function handleRetry() {
    dispatch({ type: "RESET" });
  }

  const hasResult = !!currentResult;
  const loading = appState === "loading";

  return (
    <div className="space-y-5">
      {/* Status banner */}
      {hasResult && (
        <div
          className="flex items-center justify-between rounded-xl border px-5 py-3"
          style={{ backgroundColor: "var(--panel)", borderColor: "var(--border)" }}
        >
          <div>
            <span className="text-xs font-semibold text-primary">Analysis complete</span>
            <span className="ml-2 text-xs text-muted">
              {currentResult.infiltration_timeline.length} time windows processed
              {sourceLabel && <> · <span className="font-mono">{sourceLabel}</span></>}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => dispatch({ type: "SET_VIEW", payload: "live-analysis" })}
              className="flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-violet-500 transition-colors"
            >
              View Live Analysis <ArrowRight className="h-3 w-3" />
            </button>
            <button
              onClick={handleRetry}
              className="rounded-lg border px-3 py-1.5 text-xs text-muted hover:text-primary transition-colors"
              style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--border)" }}
            >
              New upload
            </button>
          </div>
        </div>
      )}

      {/* Error */}
      {appState === "error" && (
        <ErrorPanel message={error} onRetry={handleRetry} />
      )}

      {/* Upload panel */}
      {!hasResult && (
        <div className="flex min-h-[calc(100vh-8rem)] flex-col items-center justify-center">
          <UploadPanel onUpload={handleUpload} onLoadMock={handleLoadMock} loading={loading} />
        </div>
      )}

      {/* Session stat cards */}
      {hasResult && <SessionOverview data={currentResult} />}
    </div>
  );
}
