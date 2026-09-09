import { useRef, useState } from "react";
import { Upload, FlaskConical, Loader2, FileUp } from "lucide-react";

export default function UploadPanel({ onUpload, onLoadMock, loading }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);

  function handleFiles(files) {
    if (!files?.length) return;
    const file = files[0];
    const ext = file.name.split(".").pop().toLowerCase();
    if (!["pcap", "csv"].includes(ext)) {
      alert("Please upload a .pcap or .csv file.");
      return;
    }
    onUpload(file);
  }

  function handleDrop(e) {
    e.preventDefault();
    setDragging(false);
    handleFiles(e.dataTransfer.files);
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-16">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-violet-600/10 border border-violet-500/20">
          <Loader2 className="h-8 w-8 text-violet-400 animate-spin" />
        </div>
        <p className="text-primary font-medium">Running world-model inference…</p>
        <p className="text-sm text-muted">Analyzing network flows with LSTM V4</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-6 py-16 px-6">
      {/* Drop zone */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload traffic capture file"
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => e.key === "Enter" && inputRef.current?.click()}
        className="w-full max-w-lg cursor-pointer rounded-2xl border-2 border-dashed p-10 text-center transition-all select-none"
        style={{
          borderColor: dragging ? "#8B5CF6" : "var(--border)",
          backgroundColor: dragging ? "rgba(139,92,246,0.08)" : "var(--panel)",
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.csv"
          className="hidden"
          onChange={(e) => handleFiles(e.target.files)}
        />
        <div className="flex flex-col items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-violet-600/10 border border-violet-500/20">
            <FileUp className="h-6 w-6 text-violet-400" />
          </div>
          <div>
            <p className="font-semibold text-primary">Upload traffic capture</p>
            <p className="mt-1 text-sm text-muted">
              Drag & drop a <span className="font-mono text-violet-400">.pcap</span> or{" "}
              <span className="font-mono text-violet-400">.csv</span> file, or click to browse
            </p>
          </div>
          <button
            type="button"
            className="mt-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-medium text-white hover:bg-violet-500 transition-colors"
            onClick={(e) => { e.stopPropagation(); inputRef.current?.click(); }}
          >
            <Upload className="mr-1.5 inline h-3.5 w-3.5" />
            Browse files
          </button>
        </div>
      </div>

      {/* Divider */}
      <div className="flex items-center gap-3 w-full max-w-lg">
        <div className="flex-1 h-px border-base" style={{ backgroundColor: "var(--border)" }} />
        <span className="text-xs text-muted uppercase tracking-wider">or</span>
        <div className="flex-1 h-px" style={{ backgroundColor: "var(--border)" }} />
      </div>

      {/* Load sample button */}
      <button
        type="button"
        onClick={onLoadMock}
        className="flex items-center gap-2 rounded-xl border px-6 py-3 text-sm font-medium text-primary hover:bg-violet-500/8 transition-all"
        style={{ borderColor: "var(--border)", backgroundColor: "var(--panel)" }}
      >
        <FlaskConical className="h-4 w-4 text-violet-400" />
        Load sample attack session
      </button>
    </div>
  );
}
