import { createContext, useContext, useReducer, useEffect } from "react";

// ── Initial state ──────────────────────────────────────────────────────────
const getInitialTheme = () => {
  try {
    return localStorage.getItem("sn-theme") === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
};

const initialState = {
  theme: getInitialTheme(),
  activeView: "dashboard", // dashboard | live-analysis | findings | settings | profile
  appState: "empty",       // empty | loading | loaded | error
  currentResult: null,
  sourceLabel: "",
  error: null,
  analysisHistory: [],
  notifyBrowserEnabled: false,
  hasUnreadAlert: false,
};

// ── Reducer ────────────────────────────────────────────────────────────────
function reducer(state, action) {
  switch (action.type) {
    case "SET_VIEW":
      return { ...state, activeView: action.payload };

    case "SET_THEME": {
      const theme = action.payload;
      try { localStorage.setItem("sn-theme", theme); } catch {}
      // dark:  add .dark, remove .light
      // light: add .light, remove .dark
      if (theme === "dark") {
        document.documentElement.classList.add("dark");
        document.documentElement.classList.remove("light");
      } else {
        document.documentElement.classList.add("light");
        document.documentElement.classList.remove("dark");
      }
      return { ...state, theme };
    }

    case "ANALYSIS_START":
      return { ...state, appState: "loading", error: null, sourceLabel: action.payload };

    case "ANALYSIS_SUCCESS": {
      const { result, sourceLabel } = action.payload;
      const peakProb = Math.max(...result.infiltration_timeline.map((t) => t.probability));
      const entry = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        sourceLabel: sourceLabel || "Upload",
        predicted_stage: result.predicted_stage,
        peakProbability: peakProb,
        result,
      };
      const hasUnreadAlert = peakProb >= 0.7;
      return {
        ...state,
        appState: "loaded",
        currentResult: result,
        analysisHistory: [entry, ...state.analysisHistory],
        hasUnreadAlert: hasUnreadAlert || state.hasUnreadAlert,
      };
    }

    case "ANALYSIS_ERROR":
      return { ...state, appState: "error", error: action.payload };

    case "RESET":
      return { ...state, appState: "empty", currentResult: null, error: null, sourceLabel: "" };

    case "SET_RESULT_FROM_HISTORY":
      return { ...state, currentResult: action.payload, appState: "loaded" };

    case "SET_NOTIFY_BROWSER":
      return { ...state, notifyBrowserEnabled: action.payload };

    case "CLEAR_ALERT":
      return { ...state, hasUnreadAlert: false };

    default:
      return state;
  }
}

// ── Context ────────────────────────────────────────────────────────────────
const AppContext = createContext(null);

export function AppProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, initialState);

  // Apply theme class on mount
  useEffect(() => {
    if (state.theme === "dark") {
      document.documentElement.classList.add("dark");
      document.documentElement.classList.remove("light");
    } else {
      document.documentElement.classList.add("light");
      document.documentElement.classList.remove("dark");
    }
  }, []);

  return (
    <AppContext.Provider value={{ state, dispatch }}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}
