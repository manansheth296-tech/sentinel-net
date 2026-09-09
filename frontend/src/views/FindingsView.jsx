import { FileText, ArrowLeft } from "lucide-react";
import FindingsReport from "../components/FindingsReport";
import { useApp } from "../context/AppContext";

export default function FindingsView() {
  const { state, dispatch } = useApp();
  const { currentResult } = state;

  if (!currentResult) {
    return (
      <div className="flex min-h-[calc(100vh-8rem)] flex-col items-center justify-center gap-4">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-violet-600/10 border border-violet-500/20">
          <FileText className="h-7 w-7 text-violet-400/50" />
        </div>
        <p className="text-sm font-semibold dark:text-[#E9ECF6] text-[#12131A]">No findings yet</p>
        <p className="text-xs dark:text-[#8A93B3] text-[#6B7280]">Run an analysis from the Dashboard first</p>
        <button
          onClick={() => dispatch({ type: "SET_VIEW", payload: "dashboard" })}
          className="mt-2 flex items-center gap-1.5 rounded-lg border border-[#232B45] px-4 py-2 text-sm dark:text-[#8A93B3] text-[#6B7280] hover:border-violet-500/50 hover:dark:text-[#E9ECF6] hover:text-[#12131A] transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Go to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <FindingsReport result={currentResult} />
    </div>
  );
}
