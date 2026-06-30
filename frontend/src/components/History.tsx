import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Search, 
  Eye, 
  X, 
  AlertTriangle, 
  ShieldCheck, 
  Download, 
  Globe, 
  Server, 
  Fingerprint, 
  FileText,
  RefreshCw
} from 'lucide-react';
import axios from 'axios';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';
import { API_URL, executeWithRetry } from '../config';

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

interface HistoryProps {
  triggerRefresh: boolean;
  onScanSelected: (scan: PredictResponse) => void;
}

export const History: React.FC<HistoryProps> = ({ triggerRefresh }) => {
  const [history, setHistory] = useState<PredictResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [selectedScan, setSelectedScan] = useState<PredictResponse | null>(null);
  const [modalLoading, setModalLoading] = useState(false);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await executeWithRetry(() => 
        axios.get<PredictResponse[]>(`${API_URL}/api/history?limit=50`).then(res => res.data)
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

  const filteredHistory = history.filter(item => {
    const subject = item.subject?.toLowerCase() || '';
    const sender = item.sender?.toLowerCase() || '';
    const threat = item.threat_type?.toLowerCase() || '';
    const query = search.toLowerCase();
    return subject.includes(query) || sender.includes(query) || threat.includes(query);
  });

  const handleExportPDF = async () => {
    const element = document.getElementById('audit-report-container');
    if (!element || !selectedScan) return;

    setModalLoading(true);
    try {
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
      
      const fileName = `Audit_Report_${selectedScan.id}_${(selectedScan.subject || 'scan').replace(/[^a-z0-9]/gi, '_').toLowerCase()}.pdf`;
      pdf.save(fileName);
    } catch (err) {
      console.error('PDF export failed:', err);
    } finally {
      setModalLoading(false);
    }
  };

  const formatTime = (dateStr?: string) => {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
            Incident Logs & Audits
          </h1>
          <p className="text-slate-400 text-sm mt-1 font-mono">
            Audit history, investigate IOCs, and generate PDF compliance reports.
          </p>
        </div>

        {/* Search Bar */}
        <div className="relative max-w-md w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by Subject, Sender, or Threat Type..."
            className="w-full pl-10 pr-4 py-2 bg-slate-900 border border-slate-800 focus:border-cyber-blue rounded-lg text-slate-200 placeholder-slate-650 focus:outline-none transition-all duration-300 font-mono text-xs"
          />
        </div>
      </div>

      {/* History Table */}
      <div className="glass-panel rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-20 text-center text-xs font-mono text-slate-500 flex flex-col items-center gap-2 justify-center">
            <RefreshCw className="w-6 h-6 text-cyber-blue animate-spin" />
            <span>FETCHING INCIDENT LOGS...</span>
          </div>
        ) : filteredHistory.length === 0 ? (
          <div className="p-20 text-center text-xs font-mono text-slate-500">
            NO INCIDENT LOGS FOUND MATCHING QUERY
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left font-mono">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 text-[10px] uppercase">
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">Subject</th>
                  <th className="p-4">Sender</th>
                  <th className="p-4">Classification</th>
                  <th className="p-4">Risk Rating</th>
                  <th className="p-4">Threat Vector</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-900">
                {filteredHistory.map((item) => {
                  let badgeClass = 'bg-cyber-green/10 text-cyber-green border-cyber-green/20';
                  if (item.classification === 'Suspicious') {
                    badgeClass = 'bg-cyber-yellow/10 text-cyber-yellow border-cyber-yellow/20';
                  } else if (item.classification === 'Phishing') {
                    badgeClass = 'bg-cyber-red/10 text-cyber-red border-cyber-red/20';
                  }

                  return (
                    <tr key={item.id} className="hover:bg-slate-800/25 transition-colors">
                      <td className="p-4 text-slate-450 whitespace-nowrap">{formatTime(item.created_at)}</td>
                      <td className="p-4 font-medium text-slate-200 truncate max-w-[180px]">{item.subject}</td>
                      <td className="p-4 text-slate-400 truncate max-w-[150px]">{item.sender}</td>
                      <td className="p-4">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${badgeClass}`}>
                          {item.classification.toUpperCase()}
                        </span>
                      </td>
                      <td className="p-4 font-bold text-slate-300">{item.risk_score}/100</td>
                      <td className="p-4 text-slate-400">{item.threat_type || 'General'}</td>
                      <td className="p-4 text-right whitespace-nowrap">
                        <button
                          onClick={() => setSelectedScan(item)}
                          className="px-2.5 py-1.5 bg-slate-800 hover:bg-cyber-blue hover:text-black hover:shadow-neon-blue border border-slate-700 hover:border-cyber-blue rounded-md transition-all duration-300 text-[10px] font-bold cursor-pointer"
                        >
                          <span className="flex items-center gap-1">
                            <Eye className="w-3.5 h-3.5" /> AUDIT
                          </span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Audit Modal */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md overflow-y-auto">
          <div className="glass-panel max-w-4xl w-full rounded-xl border border-slate-800 max-h-[90vh] flex flex-col text-left">
            
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-850 flex items-center justify-between font-mono text-xs">
              <span className="text-cyber-blue font-bold tracking-widest">INCIDENT AUDIT: #{selectedScan.id}</span>
              <button 
                onClick={() => setSelectedScan(null)}
                className="p-1 text-slate-450 hover:text-white rounded bg-slate-800 border border-slate-700 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body (Scrollable Report) */}
            <div className="flex-grow overflow-y-auto p-6 space-y-6" id="audit-report-container">
              
              {/* Header Status Block */}
              <div className={`p-5 rounded-lg border flex flex-col sm:flex-row justify-between items-center gap-4 ${
                selectedScan.classification === 'Phishing' 
                  ? 'bg-cyber-red/5 border-cyber-red/20 text-red-100'
                  : selectedScan.classification === 'Suspicious'
                  ? 'bg-cyber-yellow/5 border-cyber-yellow/20 text-amber-100'
                  : 'bg-cyber-green/5 border-cyber-green/20 text-emerald-100'
              }`}>
                <div className="flex items-center gap-4 text-left">
                  <div className={`p-3 rounded-xl ${
                    selectedScan.classification === 'Phishing' ? 'bg-cyber-red/10 text-cyber-red' : selectedScan.classification === 'Suspicious' ? 'bg-cyber-yellow/10 text-cyber-yellow' : 'bg-cyber-green/10 text-cyber-green'
                  }`}>
                    {selectedScan.classification === 'Safe' ? <ShieldCheck className="w-8 h-8" /> : selectedScan.classification === 'Suspicious' ? <AlertTriangle className="w-8 h-8" /> : <Shield className="w-8 h-8" />}
                  </div>
                  <div>
                    <h3 className="text-xl font-bold font-mono">{selectedScan.classification.toUpperCase()}</h3>
                    <p className="text-[10px] font-mono text-slate-450 mt-0.5">Vector: {selectedScan.threat_type || 'General'}</p>
                  </div>
                </div>

                <div className="flex gap-4 font-mono text-center">
                  <div>
                    <span className="text-[9px] text-slate-500 block">RISK RATING</span>
                    <span className="text-lg font-bold text-white block">{selectedScan.risk_score}/100</span>
                  </div>
                  <div className="border-l border-slate-800 pl-4">
                    <span className="text-[9px] text-slate-500 block">CONFIDENCE</span>
                    <span className="text-lg font-bold text-white block">{selectedScan.confidence_score}%</span>
                  </div>
                  <div className="border-l border-slate-800 pl-4">
                    <span className="text-[9px] text-slate-500 block">TIMESTAMP</span>
                    <span className="text-xs font-semibold text-slate-400 block mt-1">{formatTime(selectedScan.created_at)}</span>
                  </div>
                </div>
              </div>

              {/* Subject/Sender Metadata */}
              <div className="p-4 bg-slate-950 border border-slate-900 rounded-lg font-mono text-xs text-left space-y-2">
                <p className="truncate"><span className="text-slate-500">SUBJECT:</span> <span className="text-slate-200 font-semibold">{selectedScan.subject}</span></p>
                <p className="truncate"><span className="text-slate-500">SENDER:</span> <span className="text-slate-200 font-semibold">{selectedScan.sender}</span></p>
              </div>

              {/* Explanatory Analysis */}
              <div className="space-y-2 text-left">
                <span className="text-[10px] font-mono text-slate-500 uppercase">Executive Security Analysis</span>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/40 p-4 border border-slate-850 rounded-lg select-text">
                  {selectedScan.explanation}
                </p>
              </div>

              {/* V2 Sub Cards (WHOIS & VirusTotal) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* VirusTotal */}
                {selectedScan.virustotal_results && (
                  <div className="glass-panel p-4 rounded-lg text-left space-y-1.5">
                    <span className="text-[10px] font-mono text-slate-500 uppercase block border-b border-slate-800 pb-1 flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-cyber-blue" /> VirusTotal Registry
                    </span>
                    <p className="text-xs font-mono text-slate-300">Detections: <span className="text-cyber-red font-bold">{selectedScan.virustotal_results.malicious}</span> / {selectedScan.virustotal_results.malicious + selectedScan.virustotal_results.harmless}</p>
                    <p className="text-xs font-mono text-slate-300">Reputation: <span className="text-white font-bold">{selectedScan.virustotal_results.reputation}</span></p>
                    <div className="flex justify-between text-[9px] font-mono text-slate-500 pt-1">
                      <span className="text-cyber-green">+{selectedScan.virustotal_results.community_votes_harmless} safe</span>
                      <span className="text-cyber-red">-{selectedScan.virustotal_results.community_votes_malicious} malicious</span>
                    </div>
                  </div>
                )}

                {/* WHOIS */}
                {selectedScan.whois_results && (
                  <div className="glass-panel p-4 rounded-lg text-left space-y-1.5">
                    <span className="text-[10px] font-mono text-slate-500 uppercase block border-b border-slate-800 pb-1 flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-cyber-blue" /> WHOIS Domain Metadata
                    </span>
                    <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-[10px] font-mono text-slate-400">
                      <p className="truncate">Age: <span className="text-slate-200 font-bold">{selectedScan.whois_results.domain_age_days ?? 'N/A'} days</span></p>
                      <p className="truncate">Country: <span className="text-slate-200 font-bold">{selectedScan.whois_results.country}</span></p>
                      <p className="truncate">Registrar: <span className="text-slate-200 font-bold">{selectedScan.whois_results.registrar}</span></p>
                      <p className="truncate">Reg Date: <span className="text-slate-200 font-bold">{selectedScan.whois_results.registration_date}</span></p>
                      <p className="truncate">Expires: <span className="text-slate-200 font-bold">{selectedScan.whois_results.expiration_date}</span></p>
                      <p className="truncate">Updated: <span className="text-slate-200 font-bold">{selectedScan.whois_results.updated_date}</span></p>
                      <p className="truncate col-span-2">Name Servers: <span className="text-slate-200 font-bold" title={selectedScan.whois_results.name_servers}>{selectedScan.whois_results.name_servers}</span></p>
                    </div>
                    {selectedScan.whois_results.is_new_domain && (
                      <span className="block text-[8px] font-mono text-cyber-red font-bold text-center bg-cyber-red/10 border border-cyber-red/20 py-0.5 rounded animate-pulse mt-1">
                        ⚠️ DANGEROUS: DOMAIN AGE &lt; 90 DAYS!
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Email Authentication & Attachments */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Email Auth */}
                {selectedScan.email_auth_results && (
                  <div className="glass-panel p-4 rounded-lg text-left space-y-2">
                    <span className="text-[10px] font-mono text-slate-500 uppercase block border-b border-slate-800 pb-1 flex items-center gap-1.5">
                      <Fingerprint className="w-3.5 h-3.5 text-cyber-blue" /> Email Auth Status
                    </span>
                    <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
                      <div className="p-1 bg-slate-950 border border-slate-900 rounded">
                        <span className="text-[8px] text-slate-500 block">SPF</span>
                        <span className={`font-bold ${selectedScan.email_auth_results.spf === 'Pass' ? 'text-cyber-green' : selectedScan.email_auth_results.spf === 'Fail' ? 'text-cyber-red' : 'text-slate-400'}`}>
                          {selectedScan.email_auth_results.spf}
                        </span>
                      </div>
                      <div className="p-1 bg-slate-950 border border-slate-900 rounded">
                        <span className="text-[8px] text-slate-500 block">DKIM</span>
                        <span className={`font-bold ${selectedScan.email_auth_results.dkim === 'Pass' ? 'text-cyber-green' : selectedScan.email_auth_results.dkim === 'Fail' ? 'text-cyber-red' : 'text-slate-400'}`}>
                          {selectedScan.email_auth_results.dkim}
                        </span>
                      </div>
                      <div className="p-1 bg-slate-955 border border-slate-900 rounded">
                        <span className="text-[8px] text-slate-500 block">DMARC</span>
                        <span className={`font-bold ${selectedScan.email_auth_results.dmarc === 'Pass' ? 'text-cyber-green' : selectedScan.email_auth_results.dmarc === 'Fail' ? 'text-cyber-red' : 'text-slate-400'}`}>
                          {selectedScan.email_auth_results.dmarc}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Attachments */}
                {selectedScan.attachment_analysis && selectedScan.attachment_analysis.length > 0 && (
                  <div className="glass-panel p-4 rounded-lg text-left space-y-2">
                    <span className="text-[10px] font-mono text-slate-500 uppercase block border-b border-slate-800 pb-1 flex items-center gap-1.5">
                      <FileText className="w-3.5 h-3.5 text-cyber-blue" /> Scanned Attachments
                    </span>
                    <div className="space-y-1.5 max-h-16 overflow-y-auto pr-1">
                      {selectedScan.attachment_analysis.map((att, i) => (
                        <div key={i} className="flex justify-between items-center text-[10px] font-mono bg-slate-950 p-1 border border-slate-900 rounded">
                          <span className="text-slate-300 truncate max-w-[120px]">{att.filename}</span>
                          <span className={`px-1 rounded text-[8px] font-bold ${
                            att.risk_level === 'High' ? 'bg-cyber-red/10 text-cyber-red border border-cyber-red/20' : 'bg-cyber-green/10 text-cyber-green border border-cyber-green/20'
                          }`}>
                            {att.risk_level}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK Mapping */}
              {selectedScan.llm_analysis && (
                <div className="glass-panel p-4 rounded-lg text-left space-y-3">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block border-b border-slate-800 pb-1 flex items-center gap-1.5">
                    <Fingerprint className="w-3.5 h-3.5 text-cyber-blue" /> MITRE ATT&CK Matrix Mappings
                  </span>
                  <div className="space-y-2">
                    {selectedScan.llm_analysis.mitre_mappings.map((m, i) => (
                      <div key={i} className="p-2.5 bg-slate-950 border border-slate-900 rounded flex gap-2.5">
                        <span className="text-[9px] font-mono font-bold text-cyber-red bg-cyber-red/5 border border-cyber-red/20 px-1.5 py-0.5 rounded h-fit shrink-0">
                          {m.id}
                        </span>
                        <div className="space-y-0.5">
                          <p className="text-xs font-bold text-slate-200">{m.name}</p>
                          <p className="text-[10px] text-slate-450 leading-relaxed">{m.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Risk Heatmap */}
              {selectedScan.highlighted_text && (
                <div className="glass-panel p-4 rounded-lg text-left space-y-2">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block border-b border-slate-800 pb-1">
                    Email Heatmap
                  </span>
                  <div 
                    className="bg-slate-950 border border-slate-900 rounded p-3 font-mono text-xs text-slate-350 leading-relaxed select-text whitespace-pre-wrap max-h-36 overflow-y-auto"
                    dangerouslySetInnerHTML={{ __html: selectedScan.highlighted_text }}
                  />
                </div>
              )}

            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-850 bg-slate-900/10 flex justify-end gap-3">
              <button
                onClick={() => setSelectedScan(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-lg border border-slate-700 transition-all duration-300 cursor-pointer"
              >
                CLOSE AUDIT
              </button>
              <button
                onClick={handleExportPDF}
                disabled={modalLoading}
                className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyber-blue font-mono text-xs rounded-lg border border-slate-700 hover:border-cyber-blue transition-all duration-300 cursor-pointer"
              >
                {modalLoading ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Download className="w-3.5 h-3.5" />
                )}
                EXPORT AUDIT REPORT
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
};
