import { createContext, useContext, useState, useCallback } from "react";
import { X, AlertTriangle, Info } from "lucide-react";

const ToastContext = createContext(null);
let toastId = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(({ message, type = "info", duration = 6000 }) => {
    const id = ++toastId;
    setToasts((prev) => [...prev, { id, message, type }]);
    if (duration > 0) setTimeout(() => removeToast(id), duration);
    return id;
  }, [removeToast]);

  return (
    <ToastContext.Provider value={{ addToast, removeToast }}>
      {children}
      <div
        className="fixed bottom-5 right-5 z-[100] flex flex-col gap-2 max-w-sm"
        aria-live="polite"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            className="flex items-start gap-3 rounded-xl border px-4 py-3 shadow-2xl text-sm backdrop-blur-sm animate-in"
            style={{
              backgroundColor: t.type === "critical" ? "rgba(26,11,15,0.96)" : "var(--panel)",
              borderColor: t.type === "critical" ? "rgba(244,63,94,0.4)" : "var(--border)",
              color: "var(--text)",
            }}
          >
            <span className="mt-0.5 shrink-0">
              {t.type === "critical"
                ? <AlertTriangle className="h-4 w-4 text-rose-400" />
                : <Info className="h-4 w-4 text-violet-400" />
              }
            </span>
            <p className="flex-1 leading-snug">{t.message}</p>
            <button
              onClick={() => removeToast(t.id)}
              className="shrink-0 text-muted hover:text-primary transition-colors"
              aria-label="Dismiss"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
