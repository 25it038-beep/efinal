import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Search, 
  Filter, 
  X, 
  Download, 
  Calendar,
  User,
  Mail,
  RefreshCw,
  CheckCircle,
  XCircle,
  Flame,
  Key,
  DollarSign,
  Sparkles,
  Info,
  FileText,
  Link as LinkIcon
} from 'lucide-react';
import { executeWithRetry, apiRequest } from '../config';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

interface KeywordImportance {
  word: string;
  weight: number;
  type: string;
}

interface PredictResponse {
  id?: number;
  subject?: string;
  sender?: string;
  classification: string;
  confidence_score: number;
  risk_score: number;
  explanation: string;
  detected_indicators: Record<string, boolean>;
  highlighted_text: string;
  xai_keywords: KeywordImportance[];
  created_at?: string;
}

interface HistoryProps {
  onScanSelected: (scan: PredictResponse) => void;
  triggerRefresh: boolean;
}

export const History: React.FC<HistoryProps> = ({ triggerRefresh }) => {
  const [history, setHistory] = useState<PredictResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterClass, setFilterClass] = useState<string>('ALL');
  const [selectedScan, setSelectedScan] = useState<PredictResponse | null>(null);
  const [modalLoading, setModalLoading] = useState(false);

  const modalReportRef = useRef<HTMLDivElement>(null);


  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await executeWithRetry(() =>
        apiRequest<PredictResponse[]>('/api/history?limit=100', { method: 'get' })
      );
      setHistory(data);
    } catch (err) {
      console.error('Failed to fetch history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [triggerRefresh]);

  const handleExportPDF = async () => {
    if (!modalReportRef.current || !selectedScan) return;
    
    setModalLoading(true);
    try {
      const element = modalReportRef.current;
      const canvas = await html2canvas(element, {
        scale: 2,
        backgroundColor: '#080b11',
        logging: false
      });
      
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const imgWidth = 210;
      const pageHeight = 297;
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      let heightLeft = imgHeight;
      let position = 0;

      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;

      while (heightLeft >= 0) {
        position = heightLeft - imgHeight;
        pdf.addPage();
        pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
        heightLeft -= pageHeight;
      }
      
      const fileName = `Phishing_Report_Hist_${selectedScan.id}_${selectedScan.subject?.replace(/[^a-z0-9]/gi, '_').toLowerCase() || 'scan'}.pdf`;
      pdf.save(fileName);
    } catch (err) {
      console.error('PDF export failed:', err);
    } finally {
      setModalLoading(false);
    }
  };

  // Filter history based on search and classification dropdown
  const filteredHistory = history.filter(item => {
    const matchesSearch = 
      (item.subject?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
      (item.sender?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
      (item.explanation?.toLowerCase() || '').includes(searchTerm.toLowerCase());
    
    const matchesClass = filterClass === 'ALL' || item.classification.toUpperCase() === filterClass;
    
    return matchesSearch && matchesClass;
  });

  const formatTime = (dateStr?: string) => {
    if (!dateStr) return '';
    const date = new Date(dateStr);
    return date.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' }) + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const getIndicatorMetadata = (key: string) => {
    const meta: Record<string, { label: string, icon: any }> = {
      urgent_language: { label: 'Urgent Language', icon: Flame },
      fake_login: { label: 'Credential Harvesting', icon: Key },
      password_request: { label: 'Password Request', icon: Key },
      banking_scam: { label: 'Banking Fraud', icon: DollarSign },
      financial_fraud: { label: 'Financial Scam', icon: DollarSign },
      crypto_scam: { label: 'Cryptocurrency Scam', icon: Sparkles },
      suspicious_urls: { label: 'Suspicious URLs', icon: LinkIcon },
      spoofed_sender: { label: 'Spoofed Sender', icon: AlertTriangle },
      grammar_issues: { label: 'Grammar/Tone Issues', icon: Info },
      dangerous_attachments: { label: 'Dangerous Attachments', icon: FileText }
    };
    return meta[key] || { label: key.replace('_', ' '), icon: Info };
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
            Incident Logs
          </h1>
          <p className="text-slate-400 text-sm mt-1 font-mono">
            Browse, filter, and audit historical security scans.
          </p>
        </div>
        <button 
          onClick={fetchHistory}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 hover:border-cyber-blue transition-all duration-300 font-mono text-xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          RELOAD INCIDENTS
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col sm:flex-row gap-4">
        {/* Search Bar */}
        <div className="relative flex-grow">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search by subject, sender, or content..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-900 border border-slate-850 focus:border-cyber-blue rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none transition-all duration-300 font-mono text-xs"
          />
        </div>
        
        {/* Dropdown Filter */}
        <div className="relative min-w-[180px]">
          <Filter className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <select
            value={filterClass}
            onChange={(e) => setFilterClass(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-900 border border-slate-850 focus:border-cyber-blue rounded-lg text-slate-300 focus:outline-none transition-all duration-300 font-mono text-xs appearance-none cursor-pointer"
          >
            <option value="ALL">ALL THREAT LEVELS</option>
            <option value="SAFE">SAFE ONLY</option>
            <option value="SUSPICIOUS">SUSPICIOUS ONLY</option>
            <option value="PHISHING">PHISHING ONLY</option>
          </select>
        </div>
      </div>

      {/* Incident List */}
      <div className="glass-panel rounded-xl overflow-hidden border border-slate-850">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-900/50 border-b border-slate-850 text-xs font-mono text-slate-400 uppercase">
                <th className="p-4 pl-6">ID</th>
                <th className="p-4">Subject</th>
                <th className="p-4">Sender</th>
                <th className="p-4">Scan Date</th>
                <th className="p-4">Risk</th>
                <th className="p-4">Status</th>
                <th className="p-4 pr-6 text-right">Audit</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 text-sm">
              {loading ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-slate-500 font-mono">
                    <RefreshCw className="w-6 h-6 text-cyber-blue animate-spin mx-auto mb-2" />
                    RETRIEVING AUDIT LOGS...
                  </td>
                </tr>
              ) : filteredHistory.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-slate-500 font-mono">
                    NO CYBER INCIDENTS MATCHING FILTERS
                  </td>
                </tr>
              ) : (
                filteredHistory.map((scan) => {
                  let statusBadge = (
                    <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-cyber-green/10 text-cyber-green border border-cyber-green/20">
                      SAFE
                    </span>
                  );
                  if (scan.classification === 'Suspicious') {
                    statusBadge = (
                      <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/20">
                        SUSPICIOUS
                      </span>
                    );
                  } else if (scan.classification === 'Phishing') {
                    statusBadge = (
                      <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-cyber-red/10 text-cyber-red border border-cyber-red/20">
                        PHISHING
                      </span>
                    );
                  }

                  return (
                    <tr key={scan.id} className="hover:bg-slate-800/20 transition-colors">
                      <td className="p-4 pl-6 font-mono text-xs text-slate-500">
                        #{scan.id}
                      </td>
                      <td className="p-4 font-medium max-w-xs truncate text-slate-200">
                        {scan.subject}
                      </td>
                      <td className="p-4 text-slate-400 max-w-xs truncate font-mono text-xs">
                        {scan.sender}
                      </td>
                      <td className="p-4 text-slate-500 font-mono text-xs">
                        {formatTime(scan.created_at)}
                      </td>
                      <td className="p-4 font-mono text-xs text-slate-400">
                        {scan.risk_score}/100
                      </td>
                      <td className="p-4">
                        {statusBadge}
                      </td>
                      <td className="p-4 pr-6 text-right">
                        <button
                          onClick={() => setSelectedScan(scan)}
                          className="px-3 py-1 bg-slate-800 hover:bg-slate-700 hover:text-white text-slate-300 font-mono text-xs rounded transition-colors border border-slate-750"
                        >
                          AUDIT
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Detail Modal */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="glass-panel w-full max-w-4xl max-h-[90vh] rounded-2xl border border-slate-800 flex flex-col overflow-hidden shadow-2xl animate-in fade-in zoom-in duration-200">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-850 flex justify-between items-center bg-slate-900/50">
              <div className="flex items-center gap-3">
                <Shield className={`w-5 h-5 ${
                  selectedScan.classification === 'Phishing' 
                    ? 'text-cyber-red' 
                    : selectedScan.classification === 'Suspicious'
                    ? 'text-cyber-yellow'
                    : 'text-cyber-green'
                }`} />
                <h3 className="font-mono text-sm uppercase tracking-wider text-slate-200">
                  Incident Audit: #{selectedScan.id}
                </h3>
              </div>
              <button 
                onClick={() => setSelectedScan(null)}
                className="p-1.5 text-slate-500 hover:text-white rounded-lg bg-slate-800 border border-slate-750 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto flex-grow space-y-6 select-none" ref={modalReportRef}>
              {/* Top Banner Info */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-slate-900/40 border border-slate-850 p-4 rounded-xl">
                <div className="space-y-1.5 text-left">
                  <span className="text-[10px] font-mono text-slate-500 uppercase flex items-center gap-1"><Mail className="w-3 h-3" /> Subject</span>
                  <p className="text-xs font-medium text-slate-250 truncate">{selectedScan.subject}</p>
                </div>
                <div className="space-y-1.5 text-left">
                  <span className="text-[10px] font-mono text-slate-500 uppercase flex items-center gap-1"><User className="w-3 h-3" /> Sender</span>
                  <p className="text-xs font-mono text-slate-350 truncate">{selectedScan.sender}</p>
                </div>
                <div className="space-y-1.5 text-left">
                  <span className="text-[10px] font-mono text-slate-500 uppercase flex items-center gap-1"><Calendar className="w-3 h-3" /> Scan Date</span>
                  <p className="text-xs font-mono text-slate-350">{formatTime(selectedScan.created_at)}</p>
                </div>
              </div>

              {/* Status Banner */}
              <div className={`p-5 rounded-xl border flex flex-col md:flex-row items-center justify-between gap-4 ${
                selectedScan.classification === 'Phishing' 
                  ? 'bg-cyber-red/5 border-cyber-red/25 text-cyber-red' 
                  : selectedScan.classification === 'Suspicious'
                  ? 'bg-cyber-yellow/5 border-cyber-yellow/25 text-cyber-yellow'
                  : 'bg-cyber-green/5 border-cyber-green/25 text-cyber-green'
              }`}>
                <div className="text-left">
                  <h4 className="text-xl font-bold font-mono uppercase tracking-tight">
                    {selectedScan.classification} DETECTED
                  </h4>
                  <p className="text-xs text-slate-300 mt-1 max-w-xl leading-relaxed">
                    {selectedScan.explanation}
                  </p>
                </div>
                <div className="flex gap-4 font-mono text-center shrink-0">
                  <div className="px-4 py-1.5 bg-slate-950/80 rounded-lg border border-slate-850">
                    <span className="text-[10px] text-slate-500 uppercase block">Confidence</span>
                    <span className="text-lg font-bold text-white block mt-0.5">{selectedScan.confidence_score}%</span>
                  </div>
                  <div className="px-4 py-1.5 bg-slate-955/80 rounded-lg border border-slate-850">
                    <span className="text-[10px] text-slate-500 uppercase block">Risk Score</span>
                    <span className={`text-lg font-bold block mt-0.5 ${
                      selectedScan.risk_score > 60 ? 'text-cyber-red' : selectedScan.risk_score > 30 ? 'text-cyber-yellow' : 'text-cyber-green'
                    }`}>
                      {selectedScan.risk_score}/100
                    </span>
                  </div>
                </div>
              </div>

              {/* Indicators & XAI Chart */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Indicators list */}
                <div className="glass-panel p-4 rounded-xl space-y-3">
                  <h5 className="font-mono text-xs text-slate-300 uppercase border-b border-slate-800 pb-2">
                    Indicators Check
                  </h5>
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {Object.keys(selectedScan.detected_indicators).map((key) => {
                      const isTriggered = selectedScan.detected_indicators[key];
                      const meta = getIndicatorMetadata(key);
                      const Icon = meta.icon;
                      
                      return (
                        <div 
                          key={key} 
                          className={`flex items-center justify-between p-2 rounded-lg border text-xs ${
                            isTriggered 
                              ? 'bg-cyber-red/5 border-cyber-red/20 text-cyber-red' 
                              : 'bg-slate-900/10 border-slate-850 text-slate-400'
                          }`}
                        >
                          <div className="flex items-center gap-2">
                            <Icon className="w-3.5 h-3.5" />
                            <span className="font-medium">{meta.label}</span>
                          </div>
                          <div>
                            {isTriggered ? (
                              <XCircle className="w-4 h-4 text-cyber-red shrink-0" />
                            ) : (
                              <CheckCircle className="w-4 h-4 text-slate-600 shrink-0" />
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* XAI Chart */}
                <div className="glass-panel p-4 rounded-xl flex flex-col justify-between">
                  <h5 className="font-mono text-xs text-slate-300 uppercase border-b border-slate-800 pb-2">
                    AI Diagnostic Keywords
                  </h5>
                  <div className="h-40 mt-2">
                    {selectedScan.xai_keywords.length === 0 ? (
                      <div className="flex items-center justify-center h-full text-xs text-slate-500 font-mono">
                        NO KEYWORDS DATA SAVED
                      </div>
                    ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart 
                          data={selectedScan.xai_keywords} 
                          layout="vertical" 
                          margin={{ top: 5, right: 10, left: -15, bottom: 5 }}
                        >
                          <XAxis type="number" stroke="#475569" fontSize={8} />
                          <YAxis dataKey="word" type="category" stroke="#94a3b8" fontSize={9} width={50} fontFamily="var(--font-mono)" />
                          <Tooltip 
                            contentStyle={{ 
                              backgroundColor: '#0f172a', 
                              borderColor: '#1e293b', 
                              borderRadius: '6px', 
                              color: '#f8fafc',
                              fontSize: '10px'
                            }} 
                          />
                          <Bar dataKey="weight" radius={[0, 2, 2, 0]}>
                            {selectedScan.xai_keywords.map((entry, index) => (
                              <Cell 
                                key={`cell-${index}`} 
                                fill={entry.type === 'danger' ? '#ff3838' : '#05ffc4'} 
                              />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    )}
                  </div>
                </div>
              </div>

              {/* Heatmap */}
              <div className="glass-panel p-4 rounded-xl space-y-3">
                <h5 className="font-mono text-xs text-slate-300 uppercase border-b border-slate-800 pb-2 text-left">
                  Email Body Heatmap
                </h5>
                <div 
                  className="bg-slate-950 border border-slate-900 rounded-lg p-4 font-mono text-xs text-slate-350 leading-relaxed text-left whitespace-pre-wrap max-h-48 overflow-y-auto"
                  dangerouslySetInnerHTML={{ __html: selectedScan.highlighted_text }}
                />
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-850 bg-slate-900/50 flex justify-end gap-3">
              <button
                onClick={() => setSelectedScan(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-lg border border-slate-700 transition-colors"
              >
                CLOSE AUDIT
              </button>
              <button
                onClick={handleExportPDF}
                disabled={modalLoading}
                className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyber-blue font-mono text-xs rounded-lg border border-slate-700 hover:border-cyber-blue transition-colors disabled:text-slate-600 disabled:border-slate-800"
              >
                <Download className="w-3.5 h-3.5" />
                {modalLoading ? 'EXPORTING PDF...' : 'EXPORT REPORT AS PDF'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
