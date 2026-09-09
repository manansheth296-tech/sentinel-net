import { Shield, Sun, Moon, Bell, AlertTriangle } from "lucide-react";
import BenchmarkRow from "../components/BenchmarkRow";
import { useApp } from "../context/AppContext";

function Toggle({ checked, onChange, label, id }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <label htmlFor={id} className="text-sm text-primary cursor-pointer select-none flex-1">
        {label}
      </label>
      <button
        id={id}
        role="switch"
        aria-checked={checked}
        onClick={onChange}
        className="relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors"
        style={{ backgroundColor: checked ? "#7C3AED" : "var(--border)" }}
      >
        <span
          className="inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform"
          style={{ transform: checked ? "translateX(18px)" : "translateX(2px)" }}
        />
      </button>
    </div>
  );
}

export default function SettingsView() {
  const { state, dispatch } = useApp();
  const { theme, notifyBrowserEnabled, currentResult } = state;

  async function handleNotifyToggle() {
    if (!notifyBrowserEnabled && "Notification" in window && Notification.permission === "default") {
      const perm = await Notification.requestPermission();
      if (perm !== "granted") {
        alert("Browser notification permission denied. Enable it in browser settings.");
        return;
      }
    }
    dispatch({ type: "SET_NOTIFY_BROWSER", payload: !notifyBrowserEnabled });
  }

  const benchmarkData = currentResult?.benchmark ?? {
    world_model:       { f1: 0.8403, precision: 0.9304, recall: 0.7662, fpr: 0.0167 },
    logistic_baseline: { f1: 0.6120, precision: 0.6840, recall: 0.5540, fpr: 0.0820 },
  };

  return (
    <div className="mx-auto max-w-2xl space-y-5">
      <div className="flex items-center gap-2">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-600/10 border border-violet-500/20">
          <Shield className="h-4 w-4 text-violet-400" />
        </div>
        <h2 className="text-sm font-semibold text-primary">Settings</h2>
      </div>

      {/* Disclaimer */}
      <div className="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-5 space-y-4">
        <div className="flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-sm font-semibold text-amber-300 mb-2">Model Disclaimer</p>
            <p className="text-sm text-primary leading-relaxed">
              SentinelNet's predictions are probabilistic outputs from a machine learning model
              (World-Model LSTM). <strong>False positives and false negatives are possible.</strong>{" "}
              Always verify findings before taking action.
            </p>
          </div>
        </div>
        <div className="border-t border-amber-500/20 pt-4">
          <p className="text-xs font-semibold uppercase tracking-wider text-amber-400/70 mb-3">
            Current Model Performance
          </p>
          <BenchmarkRow benchmark={benchmarkData} />
        </div>
      </div>

      {/* Appearance */}
      <div
        className="rounded-2xl border p-5 space-y-4 transition-colors"
        style={{ backgroundColor: "var(--panel)", borderColor: "var(--border)" }}
      >
        <p className="text-xs font-semibold uppercase tracking-widest text-muted">Appearance</p>
        <Toggle
          id="theme-toggle"
          label={
            <span className="flex items-center gap-2">
              {theme === "dark"
                ? <Moon className="h-4 w-4 text-violet-400" />
                : <Sun className="h-4 w-4 text-amber-400" />
              }
              {theme === "dark" ? "Dark mode" : "Light mode"}
            </span>
          }
          checked={theme === "dark"}
          onChange={() => dispatch({ type: "SET_THEME", payload: theme === "dark" ? "light" : "dark" })}
        />
      </div>

      {/* Notifications */}
      <div
        className="rounded-2xl border p-5 space-y-4 transition-colors"
        style={{ backgroundColor: "var(--panel)", borderColor: "var(--border)" }}
      >
        <p className="text-xs font-semibold uppercase tracking-widest text-muted">Notifications</p>
        <div className="space-y-1.5">
          <Toggle
            id="browser-notify"
            label={
              <span className="flex items-center gap-2">
                <Bell className="h-4 w-4 text-muted" />
                Browser push notifications (critical risk only)
              </span>
            }
            checked={notifyBrowserEnabled}
            onChange={handleNotifyToggle}
          />
          <p className="text-xs text-muted pl-6 leading-relaxed">
            Fires when attack probability ≥ 70% and the tab is in the background. Requires permission.
          </p>
        </div>
        <div
          className="rounded-lg border px-4 py-3"
          style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--border)" }}
        >
          <p className="text-xs text-muted">
            <strong className="text-primary">In-app toasts</strong> always fire for critical results — no permission needed.
          </p>
        </div>
      </div>
    </div>
  );
}
