import { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  List, 
  Menu, 
  X
} from 'lucide-react';
import { Dashboard } from './components/Dashboard';
import { EmailAnalyzer } from './components/EmailAnalyzer';
import { History } from './components/History';
import { parseApiError, executeWithRetry, apiRequest } from './config';


interface KeywordImportance {
  word: string;
  weight: number;
  type: string;
}

interface VirusTotalResult {
  malicious: number;
  suspicious: number;
  harmless: number;
  reputation: number;
  community_votes_harmless: number;
  community_votes_malicious: number;
}

interface WhoisResult {
  domain_age_days?: number;
  registrar?: string;
  registration_date?: string;
  expiration_date?: string;
  country?: string;
  is_new_domain: boolean;
}

interface EmailAuthResult {
  spf: string;
  dkim: string;
  dmarc: string;
  is_authenticated: boolean;
}

interface AttachmentInfo {
  filename: string;
  risk_level: string;
  reason: string;
  action: string;
}

interface MitreMapping {
  id: string;
  name: string;
  description: string;
}

interface LlmAnalysisResult {
  danger_explanation: string;
  social_engineering_techniques: string[];
  indicators_of_compromise: string[];
  safety_recommendations: string[];
  mitre_mappings: MitreMapping[];
}

interface PredictResponse {
  id?: number;
  user_id?: number;
  subject?: string;
  sender?: string;
  classification: string;
  confidence_score: number;
  risk_score: number;
  explanation: string;
  detected_indicators: Record<string, boolean>;
  highlighted_text: string;
  xai_keywords?: KeywordImportance[];
  created_at?: string;
  
  threat_type?: string;
  virustotal_results?: VirusTotalResult;
  whois_results?: WhoisResult;
  email_auth_results?: EmailAuthResult;
  attachment_analysis?: AttachmentInfo[];
  llm_analysis?: LlmAnalysisResult;
  ocr_extracted_text?: string;
}



interface StatsData {
  total_scans: number;
  safe_count: number;
  suspicious_count: number;
  phishing_count: number;
  average_confidence: number;
  risk_distribution: Record<string, number>;
  daily_scans: { date: string; count: number }[];
  weekly_scans: { date: string; count: number }[];
  most_impersonated_brands: { brand: string; count: number }[];
  top_phishing_keywords: { word: string; count: number }[];
  most_dangerous_domains: { domain: string; risk: number }[];
  country_distribution: Record<string, number>;
  file_type_distribution: Record<string, number>;
  recent_scans: PredictResponse[];
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'analyzer' | 'history'>('dashboard');
  const [stats, setStats] = useState<StatsData | null>(null);
  const [loadingStats, setLoadingStats] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [triggerHistoryRefresh, setTriggerHistoryRefresh] = useState(false);
  
  // Custom Toast State
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);

  const showToast = (message: string, type: 'success' | 'error' | 'info' = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };


  const fetchStats = async () => {
    setLoadingStats(true);
    try {
      const data = await executeWithRetry(() =>
        apiRequest<StatsData>('/api/stats', { method: 'get' })
      );
      setStats(data);
    } catch (err) {
      console.error('Failed to fetch stats:', err);
      showToast(parseApiError(err), 'error');
    } finally {
      setLoadingStats(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleRefreshAll = () => {
    fetchStats();
    setTriggerHistoryRefresh(prev => !prev);
    showToast('Telemetry data refreshed', 'info');
  };

  const handleSelectScanFromDashboard = (scan: PredictResponse) => {
    setActiveTab('history');
    showToast(`Loading scan #${scan.id} for audit`, 'info');
  };

  const navigationItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'analyzer', label: 'Threat Analyzer', icon: Shield },
    { id: 'history', label: 'Incident Logs', icon: List },
  ] as const;



  return (
    <div className="flex min-h-screen bg-[#080b11] text-slate-100 cyber-grid">
      
      {/* Toast Notification */}
      {toast && (
        <div className={`fixed bottom-5 right-5 z-50 px-4 py-3 rounded-lg border shadow-2xl flex items-center gap-2.5 font-mono text-xs animate-in slide-in-from-bottom-5 duration-300 ${
          toast.type === 'error' 
            ? 'bg-cyber-red/10 border-cyber-red/30 text-cyber-red' 
            : toast.type === 'info'
            ? 'bg-cyber-blue/10 border-cyber-blue/30 text-cyber-blue'
            : 'bg-cyber-green/10 border-cyber-green/30 text-cyber-green'
        }`}>
          <div className={`w-2 h-2 rounded-full ${
            toast.type === 'error' ? 'bg-cyber-red animate-pulse' : toast.type === 'info' ? 'bg-cyber-blue' : 'bg-cyber-green'
          }`} />
          <span>{toast.message}</span>
        </div>
      )}

      {/* Mobile Sidebar Overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar Panel */}
      <aside className={`fixed inset-y-0 left-0 z-40 w-64 glass-panel border-r border-slate-850 transform lg:translate-x-0 lg:static lg:flex lg:flex-col transition-transform duration-300 ease-in-out ${
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      }`}>
        {/* Sidebar Header */}
        <div className="p-6 border-b border-slate-850 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg shadow-neon-blue border border-cyan-400/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div className="text-left">
              <h1 className="text-sm font-bold tracking-wider text-white font-mono">PHISH-DEFENSE</h1>
              <p className="text-[9px] text-cyber-blue font-mono tracking-widest uppercase">Enterprise SaaS</p>
            </div>
          </div>
          <button 
            className="lg:hidden p-1 text-slate-400 hover:text-white rounded-lg bg-slate-800/50 border border-slate-750"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Sidebar Links */}
        <nav className="flex-grow p-4 space-y-1">
          {navigationItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  setActiveTab(item.id);
                  setSidebarOpen(false);
                }}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg font-mono text-xs tracking-wide transition-all duration-300 border ${
                  isActive
                    ? 'bg-cyber-blue/10 border-cyber-blue/20 text-cyber-blue shadow-neon-blue font-semibold'
                    : 'bg-transparent border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyber-blue' : 'text-slate-400'}`} />
                {item.label.toUpperCase()}
              </button>
            );
          })}
        </nav>

        {/* Sidebar Footer */}
        <div className="p-4 border-t border-slate-855 bg-slate-900/20 text-left font-mono text-[10px] space-y-2.5">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-cyber-green animate-pulse" />
            <span className="text-slate-400 font-bold uppercase tracking-wider">SYSTEM ONLINE</span>
          </div>
          <div className="grid grid-cols-2 gap-1.5 text-[9px] text-slate-500">
            <div>CORE: <span className="text-cyber-blue">V2.0.0</span></div>
            <div>DB: <span className="text-cyber-blue">SQLITE</span></div>
            <div>ML: <span className="text-cyber-blue">ACTIVE</span></div>
            <div>XAI: <span className="text-cyber-blue">ENABLED</span></div>
          </div>
        </div>
      </aside>

      {/* Main Content Container */}
      <div className="flex-grow flex flex-col min-w-0 min-h-screen">
        
        {/* Top Navbar */}
        <header className="lg:hidden h-16 border-b border-slate-850 px-6 flex items-center justify-between bg-slate-900/30 backdrop-blur">
          <div className="flex items-center gap-2.5">
            <Shield className="w-5 h-5 text-cyber-blue" />
            <span className="font-bold text-white tracking-wider font-mono text-xs">AI THREAT GUARD</span>
          </div>
          <button 
            onClick={() => setSidebarOpen(true)}
            className="p-2 bg-slate-800/50 border border-slate-750 text-slate-300 rounded-lg"
          >
            <Menu className="w-5 h-5" />
          </button>
        </header>

        {/* Main Content Panel */}
        <main className="flex-grow p-6 md:p-8 max-w-7xl mx-auto w-full overflow-y-auto">
          {activeTab === 'dashboard' && (
            <Dashboard 
              stats={stats} 
              loading={loadingStats} 
              onRefresh={handleRefreshAll}
              onSelectScan={handleSelectScanFromDashboard}
            />
          )}
          {activeTab === 'analyzer' && (
            <EmailAnalyzer 
              onScanCompleted={fetchStats}
            />
          )}
          {activeTab === 'history' && (
            <History 
              triggerRefresh={triggerHistoryRefresh}
              onScanSelected={() => {}} 
            />
          )}

        </main>
      </div>
    </div>
  );
}
