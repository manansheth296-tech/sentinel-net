import { Bell, Settings, User, Activity, LayoutDashboard, FileText, Sun, Moon, Shield } from "lucide-react";
import { useApp } from "../context/AppContext";

const NAV_ITEMS = [
  { id: "dashboard",     label: "Dashboard",    icon: LayoutDashboard },
  { id: "live-analysis", label: "Live Analysis", icon: Activity },
  { id: "findings",      label: "Findings",      icon: FileText },
];

export default function NavBar() {
  const { state, dispatch } = useApp();
  const { activeView, currentResult, theme, hasUnreadAlert } = state;
  const hasResult = !!currentResult;

  function setView(id) {
    if (!hasResult && (id === "live-analysis" || id === "findings")) return;
    dispatch({ type: "SET_VIEW", payload: id });
  }

  function toggleTheme() {
    dispatch({ type: "SET_THEME", payload: theme === "dark" ? "light" : "dark" });
  }

  return (
    <header
      className="sticky top-0 z-50 w-full border-b border-base backdrop-blur-sm"
      style={{ backgroundColor: "color-mix(in srgb, var(--bg) 92%, transparent)" }}
    >
      <div className="mx-auto flex h-14 max-w-[1440px] items-center gap-6 px-6">

        {/* Logo */}
        <button
          onClick={() => setView("dashboard")}
          className="flex items-center gap-2 select-none"
          aria-label="Go to dashboard"
        >
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-600/20 border border-violet-500/30">
            <Shield className="h-4 w-4 text-violet-400" />
          </div>
          <span className="font-bold text-primary tracking-tight">
            Sentinel<span className="text-violet-400">Net</span>
          </span>
        </button>

        {/* Nav tabs */}
        <nav className="flex flex-1 items-center justify-center gap-1">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
            const isActive = activeView === id;
            const isDisabled = !hasResult && (id === "live-analysis" || id === "findings");
            return (
              <button
                key={id}
                onClick={() => setView(id)}
                disabled={isDisabled}
                title={isDisabled ? "Run an analysis first" : undefined}
                className={[
                  "flex items-center gap-1.5 rounded-full px-4 py-1.5 text-sm font-medium transition-all",
                  isActive
                    ? "bg-violet-600 text-white shadow-lg shadow-violet-900/30"
                    : isDisabled
                    ? "text-muted opacity-40 cursor-not-allowed"
                    : "text-muted hover:text-primary hover:bg-violet-500/10",
                ].join(" ")}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </button>
            );
          })}
        </nav>

        {/* Right icons */}
        <div className="flex items-center gap-1 text-muted">
          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            className="flex h-8 w-8 items-center justify-center rounded-lg hover:bg-violet-500/10 hover:text-primary transition-colors"
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
          >
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>

          {/* Bell */}
          <button
            className="relative flex h-8 w-8 items-center justify-center rounded-lg hover:bg-violet-500/10 hover:text-primary transition-colors"
            aria-label="Notifications"
            onClick={() => dispatch({ type: "CLEAR_ALERT" })}
          >
            <Bell className="h-4 w-4" />
            {hasUnreadAlert && (
              <span
                className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-rose-500"
                style={{ boxShadow: "0 0 0 2px var(--bg)" }}
              />
            )}
          </button>

          {/* Settings */}
          <button
            onClick={() => dispatch({ type: "SET_VIEW", payload: "settings" })}
            className={[
              "flex h-8 w-8 items-center justify-center rounded-lg transition-colors",
              activeView === "settings"
                ? "bg-violet-600/20 text-violet-400"
                : "hover:bg-violet-500/10 hover:text-primary",
            ].join(" ")}
            aria-label="Settings"
          >
            <Settings className="h-4 w-4" />
          </button>

          {/* Avatar / Profile */}
          <button
            onClick={() => dispatch({ type: "SET_VIEW", payload: "profile" })}
            className={[
              "flex h-7 w-7 items-center justify-center rounded-full border transition-all",
              activeView === "profile"
                ? "bg-violet-600/40 border-violet-500/60 text-violet-300"
                : "bg-violet-600/20 border-violet-500/30 text-violet-300 hover:bg-violet-600/35",
            ].join(" ")}
            aria-label="Profile"
          >
            <User className="h-4 w-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
