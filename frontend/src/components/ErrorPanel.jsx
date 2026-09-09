import { AlertCircle, RotateCcw } from "lucide-react";

export default function ErrorPanel({ message, onRetry }) {
  return (
    <div className="mx-auto max-w-lg rounded-2xl border border-rose-500/30 bg-rose-500/5 p-6 text-center">
      <div className="flex justify-center mb-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-rose-500/10 border border-rose-500/20">
          <AlertCircle className="h-5 w-5 text-rose-400" />
        </div>
      </div>
      <h3 className="text-sm font-semibold text-primary mb-1">Analysis failed</h3>
      <p className="text-xs text-muted mb-4 font-mono break-all">{message}</p>
      <button
        type="button"
        onClick={onRetry}
        className="inline-flex items-center gap-2 rounded-lg bg-rose-500/10 border border-rose-500/30 px-4 py-2 text-sm text-rose-400 hover:bg-rose-500/20 transition-colors"
      >
        <RotateCcw className="h-3.5 w-3.5" />
        Retry upload
      </button>
    </div>
  );
}
