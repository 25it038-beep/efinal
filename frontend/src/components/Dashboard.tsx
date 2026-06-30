import React from 'react';
import { Shield, AlertTriangle, ShieldCheck, Activity, TrendingUp, RefreshCw, Globe, Calendar } from 'lucide-react';
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  Cell,
  AreaChart,
  Area,
  PieChart,
  Pie
} from 'recharts';

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
  updated_date?: string;
  country?: string;
  name_servers?: string;
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

interface DashboardProps {
  stats: StatsData | null;
  loading: boolean;
  onRefresh: () => void;
  onSelectScan: (scan: PredictResponse) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ stats, loading, onRefresh, onSelectScan }) => {
  if (loading || !stats) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] space-y-4">
        <RefreshCw className="w-8 h-8 text-cyber-blue animate-spin" />
        <p className="text-slate-400 font-mono text-sm">LOADING ENTERPRISE THREAT INTELLIGENCE...</p>
      </div>
    );
  }

  const hasData = stats.total_scans > 0;

  // Format Pie Chart Data for File Types
  const fileTypeData = Object.keys(stats.file_type_distribution).map(key => ({
    name: key,
    value: stats.file_type_distribution[key],
    color: key === 'EML' ? '#00f2fe' : key === 'URL' ? '#f59e0b' : '#a855f7'
  })).filter(d => d.value > 0);

  // Format Pie Chart Data for Country Distribution
  const countryData = Object.keys(stats.country_distribution).map(key => ({
    name: key,
    value: stats.country_distribution[key],
    color: ['#05ffc4', '#3b82f6', '#ec4899', '#f43f5e', '#10b981'][Math.floor(Math.random() * 5)]
  })).filter(d => d.value > 0);

  // Format Risk Distribution Bar Chart
  const riskBarData = Object.keys(stats.risk_distribution).map(key => ({
    range: key,
    count: stats.risk_distribution[key]
  }));

  const formatTime = (dateStr?: string) => {
    if (!dateStr) return 'Just now';
    const date = new Date(dateStr);
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
            Threat Intelligence Center
          </h1>
          <p className="text-slate-400 text-sm mt-1 font-mono">
            SaaS Security Status: <span className="text-cyber-green">SECURE</span> | Threat Intel Database: <span className="text-cyber-blue">CONNECTED</span>
          </p>
        </div>
        <button 
          onClick={onRefresh}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 hover:border-cyber-blue transition-all duration-300 font-mono text-xs cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          REFRESH TELEMETRY
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Scanned */}
        <div className="glass-panel p-5 rounded-xl border-l-4 border-l-cyber-blue hover:shadow-neon-blue transition-all duration-300 group">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">Total Audits</p>
              <h3 className="text-3xl font-bold mt-2 font-mono group-hover:text-cyber-blue transition-colors">
                {stats.total_scans}
              </h3>
            </div>
            <div className="p-2 bg-cyber-blue/10 rounded-lg text-cyber-blue">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center text-xs text-slate-500 font-mono">
            <TrendingUp className="w-3 h-3 mr-1 text-cyber-blue" />
            SaaS Inspection Stream
          </div>
        </div>

        {/* Safe */}
        <div className="glass-panel p-5 rounded-xl border-l-4 border-l-cyber-green hover:shadow-neon-green transition-all duration-300 group">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">Safe Anomalies</p>
              <h3 className="text-3xl font-bold mt-2 font-mono text-cyber-green">
                {stats.safe_count}
              </h3>
            </div>
            <div className="p-2 bg-cyber-green/10 rounded-lg text-cyber-green">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center text-xs text-slate-500 font-mono">
            <span>{stats.total_scans > 0 ? ((stats.safe_count / stats.total_scans) * 100).toFixed(0) : 0}% clean traffic</span>
          </div>
        </div>

        {/* Suspicious */}
        <div className="glass-panel p-5 rounded-xl border-l-4 border-l-cyber-yellow hover:shadow-lg transition-all duration-300 group">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">Suspicious Vectors</p>
              <h3 className="text-3xl font-bold mt-2 font-mono text-cyber-yellow">
                {stats.suspicious_count}
              </h3>
            </div>
            <div className="p-2 bg-cyber-yellow/10 rounded-lg text-cyber-yellow">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center text-xs text-slate-500 font-mono">
            <span>Quarantined analysis required</span>
          </div>
        </div>

        {/* Phishing */}
        <div className="glass-panel p-5 rounded-xl border-l-4 border-l-cyber-red hover:shadow-neon-red transition-all duration-300 group relative overflow-hidden">
          {stats.phishing_count > 0 && (
            <div className="absolute top-0 right-0 w-24 h-24 bg-cyber-red/5 rounded-full blur-xl animate-pulse-slow pointer-events-none" />
          )}
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">Phishing Blocked</p>
              <h3 className="text-3xl font-bold mt-2 font-mono text-cyber-red">
                {stats.phishing_count}
              </h3>
            </div>
            <div className="p-2 bg-cyber-red/10 rounded-lg text-cyber-red">
              <Shield className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center text-xs text-slate-500 font-mono">
            <span className="text-cyber-red font-semibold animate-pulse">ATTACKS MITIGATED</span>
          </div>
        </div>
      </div>

      {/* Scan Trends & Brand Impersonation */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Daily Scans Trend (Area Chart) */}
        <div className="glass-panel p-5 rounded-xl lg:col-span-2 flex flex-col justify-between min-h-[320px]">
          <div>
            <h4 className="font-mono text-sm text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
              Security Audit Activity (Last 7 Days)
            </h4>
          </div>
          <div className="h-56 w-full">
            {stats.daily_scans.length === 0 ? (
              <div className="flex items-center justify-center h-full text-xs text-slate-500 font-mono">
                NO SCAN DATA AVAILABLE
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.daily_scans} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00f2fe" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#00f2fe" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" stroke="#475569" fontSize={10} fontFamily="var(--font-mono)" />
                  <YAxis stroke="#475569" fontSize={10} fontFamily="var(--font-mono)" allowDecimals={false} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#0f172a', 
                      borderColor: '#1e293b', 
                      borderRadius: '8px', 
                      color: '#f8fafc',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px'
                    }} 
                  />
                  <Area type="monotone" dataKey="count" name="Scans" stroke="#00f2fe" strokeWidth={2} fillOpacity={1} fill="url(#colorScans)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Most Impersonated Brands */}
        <div className="glass-panel p-5 rounded-xl lg:col-span-1 flex flex-col justify-between min-h-[320px]">
          <div>
            <h4 className="font-mono text-sm text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
              Most Impersonated Brands
            </h4>
          </div>
          <div className="h-56 w-full flex flex-col justify-center">
            {stats.most_impersonated_brands.length === 0 ? (
              <div className="text-center text-xs text-slate-500 font-mono py-12">
                NO IMPERSONATION ATTACKS DETECTED YET
              </div>
            ) : (
              <div className="space-y-3">
                {stats.most_impersonated_brands.map((item, i) => (
                  <div key={i} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-300">{item.brand}</span>
                      <span className="text-cyber-blue font-bold">{item.count} attacks</span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                      <div 
                        className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 shadow-neon-blue"
                        style={{ width: `${(item.count / Math.max(...stats.most_impersonated_brands.map(b => b.count))) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Keyword Importance & File Types */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Phishing Keywords (Bar Chart) */}
        <div className="glass-panel p-5 rounded-xl lg:col-span-1 flex flex-col justify-between min-h-[320px]">
          <div>
            <h4 className="font-mono text-sm text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
              Top Phishing Keywords
            </h4>
          </div>
          <div className="h-56 w-full">
            {stats.top_phishing_keywords.length === 0 ? (
              <div className="flex items-center justify-center h-full text-xs text-slate-500 font-mono">
                NO ATTACK KEYWORDS DETECTED
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.top_phishing_keywords} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <XAxis dataKey="word" stroke="#475569" fontSize={10} fontFamily="var(--font-mono)" />
                  <YAxis stroke="#475569" fontSize={10} fontFamily="var(--font-mono)" allowDecimals={false} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#0f172a', 
                      borderColor: '#1e293b', 
                      borderRadius: '8px', 
                      color: '#f8fafc',
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)'
                    }} 
                  />
                  <Bar dataKey="count" name="Frequency" fill="#ff3838" radius={[4, 4, 0, 0]}>
                    {stats.top_phishing_keywords.map((_, index) => (
                      <Cell key={`cell-${index}`} fill="#ff3838" opacity={1 - index * 0.12} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Vector File Type Breakdown (Pie Chart) */}
        <div className="glass-panel p-5 rounded-xl lg:col-span-1 flex flex-col justify-between min-h-[320px]">
          <div>
            <h4 className="font-mono text-sm text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
              Scanned Threat Vectors
            </h4>
          </div>
          <div className="h-48 relative flex items-center justify-center">
            {fileTypeData.length === 0 ? (
              <div className="text-xs text-slate-500 font-mono">NO THREAT VECTORS AUDITED</div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={fileTypeData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={70}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {fileTypeData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute flex flex-col items-center justify-center font-mono">
                  <span className="text-2xl font-bold text-white">{stats.total_scans}</span>
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider">Audits</span>
                </div>
              </>
            )}
          </div>
          {/* Legend */}
          <div className="grid grid-cols-3 gap-1 text-center text-[10px] font-mono mt-2 border-t border-slate-900 pt-3">
            {fileTypeData.map((item, i) => (
              <div key={i} className="flex flex-col items-center">
                <div className="w-2 h-2 rounded-full mb-1" style={{ backgroundColor: item.color }} />
                <span className="text-slate-400">{item.name} ({item.value})</span>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Origin Countries */}
        <div className="glass-panel p-5 rounded-xl lg:col-span-1 flex flex-col justify-between min-h-[320px]">
          <div>
            <h4 className="font-mono text-sm text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
              Threat Origin Geography
            </h4>
          </div>
          <div className="h-56 w-full flex flex-col justify-center">
            {countryData.length === 0 ? (
              <div className="text-center text-xs text-slate-500 font-mono py-12">
                NO ORIGIN GEOGRAPHIES MAPPED
              </div>
            ) : (
              <div className="space-y-3 overflow-y-auto max-h-48 pr-1">
                {countryData.map((item, i) => (
                  <div key={i} className="flex items-center justify-between text-xs font-mono p-2 bg-slate-950 rounded border border-slate-900">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-cyber-blue" />
                      <span className="text-slate-300 font-bold">{item.name}</span>
                    </div>
                    <span className="text-slate-400">{item.value} domains</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Threat Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Score Distribution */}
        <div className="glass-panel p-5 rounded-xl lg:col-span-1 flex flex-col justify-between min-h-[320px]">
          <div>
            <h4 className="font-mono text-sm text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
              Risk Score Distribution
            </h4>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskBarData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <XAxis dataKey="range" stroke="#475569" fontSize={10} fontFamily="var(--font-mono)" />
                <YAxis stroke="#475569" fontSize={10} fontFamily="var(--font-mono)" allowDecimals={false} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#0f172a', 
                    borderColor: '#1e293b', 
                    borderRadius: '8px', 
                    color: '#f8fafc',
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)'
                  }} 
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskBarData.map((entry, index) => {
                    let color = '#05ffc4';
                    if (entry.range === '41-60') color = '#fbbf24';
                    if (entry.range === '61-80') color = '#f97316';
                    if (entry.range === '81-100') color = '#ef4444';
                    return <Cell key={`cell-${index}`} fill={color} />;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Timeline (Chronological logs) */}
        <div className="glass-panel p-5 rounded-xl lg:col-span-2 flex flex-col justify-between min-h-[320px]">
          <div>
            <h4 className="font-mono text-sm text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
              Incident Response Timeline
            </h4>
          </div>
          <div className="flex-grow overflow-y-auto max-h-56 pr-1 space-y-4">
            {!hasData ? (
              <div className="text-center text-xs text-slate-500 font-mono py-16">
                NO ACTIVE SECURITY INCIDENTS RECORDED
              </div>
            ) : (
              <div className="relative pl-6 border-l border-slate-800 space-y-4 ml-3 py-1">
                {stats.recent_scans.map((scan) => {
                  let indicatorColor = 'bg-cyber-green';
                  let iconBg = 'bg-cyber-green/10 text-cyber-green border-cyber-green/20';
                  if (scan.classification === 'Suspicious') {
                    indicatorColor = 'bg-cyber-yellow';
                    iconBg = 'bg-cyber-yellow/10 text-cyber-yellow border-cyber-yellow/20';
                  } else if (scan.classification === 'Phishing') {
                    indicatorColor = 'bg-cyber-red';
                    iconBg = 'bg-cyber-red/10 text-cyber-red border-cyber-red/20';
                  }

                  return (
                    <div key={scan.id} className="relative group text-left">
                      {/* Timeline Dot */}
                      <div className={`absolute -left-[30px] top-1.5 w-2 h-2 rounded-full border border-[#080b11] ${indicatorColor} group-hover:scale-125 transition-transform`} />
                      
                      <div className="glass-panel hover:bg-slate-800/20 p-3 rounded-lg border border-slate-850 flex items-start justify-between gap-4 transition-all">
                        <div className="space-y-1 truncate">
                          <span className="text-[9px] font-mono text-slate-500 flex items-center gap-1">
                            <Calendar className="w-3 h-3" /> {formatTime(scan.created_at)}
                          </span>
                          <h5 className="text-xs font-semibold text-slate-200 truncate">{scan.subject}</h5>
                          <p className="text-[10px] font-mono text-slate-450 truncate">Sender: {scan.sender}</p>
                          {scan.threat_type && (
                            <span className="inline-block text-[8px] font-mono font-bold bg-slate-900 text-slate-400 px-1.5 py-0.5 rounded border border-slate-800 mt-1">
                              {scan.threat_type.toUpperCase()}
                            </span>
                          )}
                        </div>
                        
                        <div className="flex flex-col items-end shrink-0 justify-between h-full space-y-2">
                          <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border ${iconBg}`}>
                            {scan.classification.toUpperCase()}
                          </span>
                          <button 
                            onClick={() => onSelectScan(scan)}
                            className="text-[9px] font-mono text-cyber-blue hover:underline cursor-pointer"
                          >
                            AUDIT &rarr;
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
