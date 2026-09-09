import NavBar from "./components/NavBar";
import DashboardView from "./views/DashboardView";
import LiveAnalysisView from "./views/LiveAnalysisView";
import FindingsView from "./views/FindingsView";
import SettingsView from "./views/SettingsView";
import ProfileView from "./views/ProfileView";
import { useApp } from "./context/AppContext";

export default function App() {
  const { state } = useApp();
  const { activeView } = state;

  const viewMap = {
    "dashboard":     <DashboardView />,
    "live-analysis": <LiveAnalysisView />,
    "findings":      <FindingsView />,
    "settings":      <SettingsView />,
    "profile":       <ProfileView />,
  };

  return (
    /* bg-surface and text-primary pick up CSS vars — no JS class swapping needed */
    <div className="min-h-screen bg-surface text-primary transition-colors duration-200">
      <NavBar />
      <main className="mx-auto max-w-[1440px] px-6 py-6">
        {viewMap[activeView] ?? <DashboardView />}
      </main>
    </div>
  );
}
