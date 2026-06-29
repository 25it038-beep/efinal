import React, { useState, useRef } from 'react';
import { 
  Shield, 
  ShieldCheck, 
  AlertTriangle, 
  Upload, 
  FileText, 
  Trash2, 
  Download, 
  Info,
  CheckCircle,
  XCircle,
  RefreshCw,
  Globe,
  HelpCircle,
  Server, 
  Fingerprint, 
  Eye
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import confetti from 'canvas-confetti';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';
import { API_URL, parseApiError, executeWithRetry } from '../config';

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

interface UrlAnalyzeResponse {
  id?: number;
  url: string;
  domain: string;
  risk_score: number;
  status: string; // "Safe", "Suspicious", "Dangerous"
  reasons: string[];
  threat_type: string;
  advice: string;
  created_at?: string;
  virustotal_results?: VirusTotalResult;
  whois_results?: WhoisResult;
}

interface EmailAnalyzerProps {
  onScanCompleted: () => void;
}

export const EmailAnalyzer: React.FC<EmailAnalyzerProps> = ({ onScanCompleted }) => {
  const [activeMode, setActiveMode] = useState<'email' | 'url'>('email');
  
  // Email Mode State
  const [inputText, setInputText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [emailResult, setEmailResult] = useState<PredictResponse | null>(null);
  
  // URL Mode State
  const [inputUrl, setInputUrl] = useState('');
  const [urlResult, setUrlResult] = useState<UrlAnalyzeResponse | null>(null);

  // Common State
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const emailReportRef = useRef<HTMLDivElement>(null);
  const urlReportRef = useRef<HTMLDivElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    setError(null);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      validateAndSetFile(droppedFile);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      validateAndSetFile(selectedFile);
    }
  };

  const validateAndSetFile = (file: File) => {
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (ext !== 'txt' && ext !== 'eml') {
      setError('Unsupported file type. Please upload only .txt or .eml files.');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setError('File size exceeds the 10MB limit.');
      return;
    }
    setFile(file);
    setInputText('');
  };

  const removeFile = () => {
    setFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const triggerConfetti = () => {
    const duration = 2 * 1000;
    const animationEnd = Date.now() + duration;
    const defaults = { startVelocity: 30, spread: 360, ticks: 60, zIndex: 1000 };

    const randomInRange = (min: number, max: number) => {
      return Math.random() * (max - min) + min;
    };

    const interval: any = setInterval(function() {
      const timeLeft = animationEnd - Date.now();

      if (timeLeft <= 0) {
        return clearInterval(interval);
      }

      const particleCount = 50 * (timeLeft / duration);
      confetti({ ...defaults, particleCount, origin: { x: randomInRange(0.1, 0.3), y: Math.random() - 0.2 }, colors: ['#00f2fe', '#05ffc4'] });
      confetti({ ...defaults, particleCount, origin: { x: randomInRange(0.7, 0.9), y: Math.random() - 0.2 }, colors: ['#00f2fe', '#05ffc4'] });
    }, 250);
  };

  const handleEmailScan = async () => {
    if (!inputText.trim() && !file) {
      setError('Please enter email text or upload a file to scan.');
      return;
    }

    setLoading(true);
    setError(null);
    setEmailResult(null);

    try {
      const data = await executeWithRetry(async () => {
        if (file) {
          const formData = new FormData();
          formData.append('file', file);
          return axios.post<PredictResponse>(`${API_URL}/api/upload`, formData, {
            headers: { 'Content-Type': 'multipart/form-data' }
          }).then(res => res.data);
        } else {
          return axios.post<PredictResponse>(`${API_URL}/api/predict`, {
            text: inputText
          }).then(res => res.data);
        }
      });

      setEmailResult(data);
      onScanCompleted();

      if (data.classification === 'Safe') {
        triggerConfetti();
      }
    } catch (err: any) {
      console.error(err);
      setError(parseApiError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleUrlScan = async () => {
    if (!inputUrl.trim()) {
      setError('Please enter a URL to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    setUrlResult(null);

    try {
      const data = await executeWithRetry(() => 
        axios.post<UrlAnalyzeResponse>(`${API_URL}/api/analyze-url`, {
          url: inputUrl.trim()
        }).then(res => res.data)
      );

      setUrlResult(data);
      onScanCompleted();

      if (data.status === 'Safe') {
        triggerConfetti();
      }
    } catch (err: any) {
      console.error(err);
      setError(parseApiError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleExportPDF = async (mode: 'email' | 'url') => {
    const reportElement = mode === 'email' ? emailReportRef.current : urlReportRef.current;
    const resultData = mode === 'email' ? emailResult : urlResult;
    
    if (!reportElement || !resultData) return;
    
    setLoading(true);
    try {
      const canvas = await html2canvas(reportElement, {
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
      
      const nameTag = mode === 'email' 
        ? (emailResult?.subject || 'email_scan')
        : (urlResult?.domain || 'url_scan');
        
      const fileName = `Threat_Report_${nameTag.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.pdf`;
      pdf.save(fileName);
    } catch (err) {
      console.error('PDF export failed:', err);
      setError('Failed to generate PDF report.');
    } finally {
      setLoading(false);
    }
  };


  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
            Threat Vector Analysis
          </h1>
          <p className="text-slate-400 text-sm mt-1 font-mono">
            Scan files, raw email text, or target URLs for malicious signatures and heuristics.
          </p>
        </div>

        {/* Mode Selector Tabs */}
        <div className="flex bg-slate-900 p-1 rounded-xl border border-slate-800 self-start md:self-auto">
          <button
            onClick={() => {
              setActiveMode('email');
              setError(null);
            }}
            className={`px-4 py-1.5 rounded-lg font-mono text-xs tracking-wider transition-all duration-300 cursor-pointer ${
              activeMode === 'email'
                ? 'bg-cyber-blue text-black font-bold shadow-neon-blue'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            EMAIL SCANNER
          </button>
          <button
            onClick={() => {
              setActiveMode('url');
              setError(null);
            }}
            className={`px-4 py-1.5 rounded-lg font-mono text-xs tracking-wider transition-all duration-300 cursor-pointer ${
              activeMode === 'url'
                ? 'bg-cyber-blue text-black font-bold shadow-neon-blue'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            URL ANALYZER
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* Left Column: Input Panel */}
        <div className="lg:col-span-4 space-y-4">
          <div className="glass-panel p-5 rounded-xl space-y-4">
            <h3 className="font-mono text-sm text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2">
              {activeMode === 'email' ? 'Email Input Stream' : 'Target URL'}
            </h3>

            {activeMode === 'email' ? (
              <>
                {/* Paste Text Area */}
                {!file && (
                  <div className="space-y-2">
                    <label className="block text-xs font-mono text-slate-400 uppercase">Paste Email Content</label>
                    <textarea
                      value={inputText}
                      onChange={(e) => {
                        setInputText(e.target.value);
                        setError(null);
                      }}
                      placeholder="Paste the full email headers and body here..."
                      className="w-full h-64 bg-slate-950 border border-slate-800 focus:border-cyber-blue rounded-lg p-3 text-slate-200 placeholder-slate-650 focus:outline-none transition-all duration-300 font-mono text-xs resize-none"
                    />
                  </div>
                )}

                {/* Drag & Drop File Zone */}
                {!inputText.trim() && (
                  <div className="space-y-2">
                    <label className="block text-xs font-mono text-slate-400 uppercase">Or Upload Email File</label>
                    {!file ? (
                      <div
                        onDragOver={handleDragOver}
                        onDragLeave={handleDragLeave}
                        onDrop={handleDrop}
                        onClick={() => fileInputRef.current?.click()}
                        className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all duration-300 ${
                          isDragOver 
                            ? 'border-cyber-blue bg-cyber-blue/5' 
                            : 'border-slate-850 hover:border-slate-700 bg-slate-950/50'
                        }`}
                      >
                        <input
                          type="file"
                          ref={fileInputRef}
                          onChange={handleFileChange}
                          accept=".txt,.eml"
                          className="hidden"
                        />
                        <Upload className={`w-8 h-8 mx-auto mb-3 transition-colors ${isDragOver ? 'text-cyber-blue' : 'text-slate-500'}`} />
                        <p className="text-xs text-slate-300 font-medium">Drag & drop your file here, or <span className="text-cyber-blue hover:underline">browse</span></p>
                        <p className="text-[10px] text-slate-500 mt-2 font-mono">Accepts .txt or .eml files (Max 10MB)</p>
                      </div>
                    ) : (
                      <div className="flex items-center justify-between p-3 bg-slate-900 border border-slate-800 rounded-lg">
                        <div className="flex items-center gap-2.5">
                          <FileText className="w-5 h-5 text-cyber-blue" />
                          <div className="text-left">
                            <p className="text-xs font-medium text-slate-200 max-w-[150px] truncate">{file.name}</p>
                            <p className="text-[10px] text-slate-500 font-mono">{(file.size / 1024).toFixed(1)} KB</p>
                          </div>
                        </div>
                        <button 
                          onClick={removeFile}
                          className="p-1 text-slate-500 hover:text-cyber-red transition-colors cursor-pointer"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </>
            ) : (
              /* URL Input Mode */
              <div className="space-y-3 text-left">
                <label className="block text-xs font-mono text-slate-400 uppercase">Paste Destination URL</label>
                <div className="relative">
                  <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <input
                    type="text"
                    value={inputUrl}
                    onChange={(e) => {
                      setInputUrl(e.target.value);
                      setError(null);
                    }}
                    placeholder="e.g. http://paypal-security-update-center.com"
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 focus:border-cyber-blue rounded-lg text-slate-200 placeholder-slate-650 focus:outline-none transition-all duration-300 font-mono text-xs"
                  />
                </div>
                <div className="p-3 bg-slate-900/50 rounded-lg text-[10px] text-slate-500 font-mono leading-relaxed flex gap-2">
                  <Info className="w-3.5 h-3.5 text-cyber-blue shrink-0" />
                  <span>
                    Audits links against the VirusTotal API, checks registrar metadata via WHOIS, and checks for typosquatting brand-hijackings.
                  </span>
                </div>
              </div>
            )}

            {error && (
              <div className="p-3 bg-cyber-red/10 border border-cyber-red/20 rounded-lg text-xs text-cyber-red font-mono flex items-start gap-2 animate-pulse">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button
              onClick={activeMode === 'email' ? handleEmailScan : handleUrlScan}
              disabled={loading || (activeMode === 'email' ? (!inputText.trim() && !file) : !inputUrl.trim())}
              className={`w-full py-2.5 rounded-lg font-mono text-sm tracking-wide transition-all duration-300 cursor-pointer ${
                loading
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold shadow-neon-blue border border-cyan-400/20 hover:border-cyan-400/40'
              }`}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  ANALYZING THREATS...
                </span>
              ) : (
                activeMode === 'email' ? 'EXECUTE EMAIL SCAN' : 'ANALYZE URL REPUTATION'
              )}
            </button>
          </div>
        </div>

        {/* Right Column: Results Panel */}
        <div className="lg:col-span-8">
          <AnimatePresence mode="wait">
            
            {/* 1. Email Mode Awaiting */}
            {activeMode === 'email' && !emailResult && (
              <motion.div
                key="email-await"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="glass-panel p-10 rounded-xl border border-slate-800 flex flex-col items-center justify-center text-center min-h-[465px]"
              >
                <div className="p-4 bg-slate-900/50 border border-slate-850 rounded-2xl mb-4 text-slate-500">
                  <Shield className="w-12 h-12" />
                </div>
                <h4 className="font-mono text-sm text-slate-300 uppercase tracking-wider">Awaiting Email Target</h4>
                <p className="text-xs text-slate-500 mt-2 max-w-sm">
                  Input email text or upload a document in the left panel and click 'Execute Email Scan' to run AI threat diagnostics.
                </p>
              </motion.div>
            )}

            {/* 2. URL Mode Awaiting */}
            {activeMode === 'url' && !urlResult && (
              <motion.div
                key="url-await"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="glass-panel p-10 rounded-xl border border-slate-800 flex flex-col items-center justify-center text-center min-h-[465px]"
              >
                <div className="p-4 bg-slate-900/50 border border-slate-850 rounded-2xl mb-4 text-slate-500">
                  <Globe className="w-12 h-12" />
                </div>
                <h4 className="font-mono text-sm text-slate-300 uppercase tracking-wider">Awaiting URL Target</h4>
                <p className="text-xs text-slate-500 mt-2 max-w-sm">
                  Paste a link in the left panel and click 'Analyze URL Reputation' to scan the host against security reputation databases.
                </p>
              </motion.div>
            )}

            {/* 3. Email Results */}
            {activeMode === 'email' && emailResult && (
              <motion.div
                key="email-result"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="space-y-4"
              >
                <div ref={emailReportRef} className="space-y-4 p-1.5 rounded-2xl bg-[#080b11]">
                  {/* Shield Alert Banner */}
                  <div className={`p-6 rounded-xl border relative overflow-hidden ${
                    emailResult.classification === 'Phishing' 
                      ? 'glass-panel-glow-red' 
                      : emailResult.classification === 'Suspicious'
                      ? 'border-cyber-yellow/30 bg-slate-900/40 shadow-lg'
                      : 'glass-panel-glow-green'
                  }`}>
                    <div className="flex flex-col md:flex-row items-center justify-between gap-6 relative z-10">
                      <div className="flex items-center gap-4 text-left">
                        <div className={`p-3.5 rounded-2xl ${
                          emailResult.classification === 'Phishing' 
                            ? 'bg-cyber-red/10 text-cyber-red' 
                            : emailResult.classification === 'Suspicious'
                            ? 'bg-cyber-yellow/10 text-cyber-yellow'
                            : 'bg-cyber-green/10 text-cyber-green'
                        }`}>
                          {emailResult.classification === 'Safe' ? (
                            <ShieldCheck className="w-10 h-10" />
                          ) : emailResult.classification === 'Suspicious' ? (
                            <AlertTriangle className="w-10 h-10" />
                          ) : (
                            <Shield className="w-10 h-10 animate-pulse-slow" />
                          )}
                        </div>
                        <div>
                          <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">SaaS Diagnostic Audit</p>
                          <h2 className={`text-3xl font-extrabold mt-1 font-mono tracking-tight ${
                            emailResult.classification === 'Phishing' 
                              ? 'text-cyber-red' 
                              : emailResult.classification === 'Suspicious'
                              ? 'text-cyber-yellow'
                              : 'text-cyber-green'
                          }`}>
                            {emailResult.classification.toUpperCase()}
                          </h2>
                          {emailResult.threat_type && (
                            <span className="inline-block mt-1 text-[9px] font-mono font-bold bg-slate-950 text-slate-400 px-2 py-0.5 rounded border border-slate-800">
                              VECTOR: {emailResult.threat_type.toUpperCase()}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex gap-6">
                        <div className="text-center font-mono">
                          <span className="text-xs text-slate-500 uppercase block">ML Confidence</span>
                          <span className="text-2xl font-bold text-white block mt-1">{emailResult.confidence_score}%</span>
                        </div>
                        <div className="text-center font-mono border-l border-slate-800 pl-6">
                          <span className="text-xs text-slate-500 uppercase block">Risk Rating</span>
                          <span className={`text-2xl font-bold block mt-1 ${
                            emailResult.risk_score > 60 ? 'text-cyber-red' : emailResult.risk_score > 30 ? 'text-cyber-yellow' : 'text-cyber-green'
                          }`}>
                            {emailResult.risk_score}/100
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="mt-5 p-3 bg-slate-955 border border-slate-850 rounded-lg text-xs text-slate-300 leading-relaxed text-left">
                      <p>{emailResult.explanation}</p>
                    </div>
                  </div>

                  {/* Threat Intel Sub-Cards Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* VirusTotal Reputation Card */}
                    {emailResult.virustotal_results && (
                      <div className="glass-panel p-4 rounded-xl text-left space-y-2">
                        <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-1.5 flex items-center gap-1.5">
                          <Server className="w-4 h-4 text-cyber-blue" /> VirusTotal URL Registry
                        </h4>
                        <div className="grid grid-cols-2 gap-2 pt-1 font-mono text-xs">
                          <div className="bg-slate-950 p-2 rounded border border-slate-900 text-center">
                            <span className="text-[9px] text-slate-550 block">DETECTIONS</span>
                            <span className={`text-base font-bold ${emailResult.virustotal_results.malicious > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
                              {emailResult.virustotal_results.malicious} / {emailResult.virustotal_results.malicious + emailResult.virustotal_results.harmless}
                            </span>
                          </div>
                          <div className="bg-slate-955 p-2 rounded border border-slate-900 text-center">
                            <span className="text-[9px] text-slate-550 block">VOTE REPUTATION</span>
                            <span className="text-base font-bold text-white">
                              {emailResult.virustotal_results.reputation}
                            </span>
                          </div>
                        </div>
                        <div className="flex justify-between text-[10px] font-mono text-slate-500 px-1">
                          <span>Community Votes:</span>
                          <span className="text-cyber-green">+{emailResult.virustotal_results.community_votes_harmless} harmless</span>
                          <span className="text-cyber-red">-{emailResult.virustotal_results.community_votes_malicious} malicious</span>
                        </div>
                      </div>
                    )}

                    {/* WHOIS Domain Registration Card */}
                    {emailResult.whois_results && (
                      <div className="glass-panel p-4 rounded-xl text-left space-y-2">
                        <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-1.5 flex items-center gap-1.5">
                          <Globe className="w-4 h-4 text-cyber-blue" /> WHOIS Domain Metadata
                        </h4>
                        <div className="grid grid-cols-2 gap-2 text-[10px] font-mono text-slate-400">
                          <p className="truncate">Age: <span className="text-slate-200 font-bold">{emailResult.whois_results.domain_age_days ?? 'N/A'} days</span></p>
                          <p className="truncate">Country: <span className="text-slate-200 font-bold">{emailResult.whois_results.country}</span></p>
                          <p className="truncate">Registrar: <span className="text-slate-200 font-bold">{emailResult.whois_results.registrar}</span></p>
                          <p className="truncate">Registered: <span className="text-slate-200 font-bold">{emailResult.whois_results.registration_date}</span></p>
                        </div>
                        {emailResult.whois_results.is_new_domain && (
                          <div className="p-1.5 bg-cyber-red/10 border border-cyber-red/20 rounded text-[9px] font-mono text-cyber-red font-bold text-center animate-pulse">
                            ⚠️ NEW DOMAIN WARNING: REGISTERED &lt; 90 DAYS AGO!
                          </div>
                        )}
                      </div>
                    )}

                    {/* Email Header Authentication Results */}
                    {emailResult.email_auth_results && (
                      <div className="glass-panel p-4 rounded-xl text-left space-y-2 col-span-1">
                        <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-1.5 flex items-center gap-1.5">
                          <Fingerprint className="w-4 h-4 text-cyber-blue" /> Email Auth Headers
                        </h4>
                        <div className="grid grid-cols-3 gap-2 pt-1 font-mono text-xs text-center">
                          <div className="p-1.5 bg-slate-950 border border-slate-900 rounded">
                            <span className="text-[9px] text-slate-500 block">SPF</span>
                            <span className={`font-bold ${emailResult.email_auth_results.spf === 'Pass' ? 'text-cyber-green' : emailResult.email_auth_results.spf === 'Fail' ? 'text-cyber-red' : 'text-slate-400'}`}>
                              {emailResult.email_auth_results.spf}
                            </span>
                          </div>
                          <div className="p-1.5 bg-slate-950 border border-slate-900 rounded">
                            <span className="text-[9px] text-slate-500 block">DKIM</span>
                            <span className={`font-bold ${emailResult.email_auth_results.dkim === 'Pass' ? 'text-cyber-green' : emailResult.email_auth_results.dkim === 'Fail' ? 'text-cyber-red' : 'text-slate-400'}`}>
                              {emailResult.email_auth_results.dkim}
                            </span>
                          </div>
                          <div className="p-1.5 bg-slate-955 border border-slate-900 rounded">
                            <span className="text-[9px] text-slate-500 block">DMARC</span>
                            <span className={`font-bold ${emailResult.email_auth_results.dmarc === 'Pass' ? 'text-cyber-green' : emailResult.email_auth_results.dmarc === 'Fail' ? 'text-cyber-red' : 'text-slate-400'}`}>
                              {emailResult.email_auth_results.dmarc}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Threat Indicators Overview (ML + Rules) */}
                    <div className="glass-panel p-4 rounded-xl text-left space-y-2 col-span-1">
                      <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-1.5">
                        Core Vector Indicators
                      </h4>
                      <div className="flex flex-wrap gap-1.5 max-h-16 overflow-y-auto pr-1">
                        {Object.keys(emailResult.detected_indicators).map((key) => {
                          if (!emailResult.detected_indicators[key]) return null;
                          return (
                            <span key={key} className="text-[8px] font-mono font-bold bg-cyber-red/10 text-cyber-red border border-cyber-red/20 px-1.5 py-0.5 rounded uppercase">
                              {key.replace('_', ' ')}
                            </span>
                          );
                        })}
                        {Object.values(emailResult.detected_indicators).every(v => !v) && (
                          <span className="text-[8px] font-mono font-bold bg-cyber-green/10 text-cyber-green border border-cyber-green/20 px-1.5 py-0.5 rounded uppercase w-full text-center">
                            NO THREAT SIGNATURES TRIGGERED
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* OCR Screenshot Scan Card */}
                  {emailResult.ocr_extracted_text && (
                    <div className="glass-panel p-5 rounded-xl text-left space-y-2">
                      <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                        <Eye className="w-4 h-4 text-cyber-blue" />
                        <span>OCR Image Text Extraction</span>
                      </h4>
                      <div className="p-3 bg-slate-950 border border-slate-900 rounded-lg font-mono text-xs text-slate-300 leading-relaxed max-h-32 overflow-y-auto">
                        <p>{emailResult.ocr_extracted_text}</p>
                      </div>
                    </div>
                  )}

                  {/* Attachment Security Audit Table */}
                  {emailResult.attachment_analysis && emailResult.attachment_analysis.length > 0 && (
                    <div className="glass-panel p-5 rounded-xl text-left space-y-3">
                      <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2">
                        Attachment Security Audit
                      </h4>
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs text-left font-mono">
                          <thead>
                            <tr className="border-b border-slate-800 text-slate-400 text-[10px] uppercase">
                              <th className="pb-2">Filename</th>
                              <th className="pb-2">Risk</th>
                              <th className="pb-2">Vulnerability Vector</th>
                              <th className="pb-2 text-right">SOC Recommendation</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-900">
                            {emailResult.attachment_analysis.map((att, i) => (
                              <tr key={i} className="hover:bg-slate-900/30">
                                <td className="py-2.5 font-medium text-slate-200">{att.filename}</td>
                                <td className="py-2.5">
                                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${
                                    att.risk_level === 'High' 
                                      ? 'bg-cyber-red/10 text-cyber-red border-cyber-red/20' 
                                      : att.risk_level === 'Medium'
                                      ? 'bg-cyber-yellow/10 text-cyber-yellow border-cyber-yellow/20'
                                      : 'bg-cyber-green/10 text-cyber-green border-cyber-green/20'
                                  }`}>
                                    {att.risk_level.toUpperCase()}
                                  </span>
                                </td>
                                <td className="py-2.5 text-slate-400 max-w-xs truncate">{att.reason}</td>
                                <td className="py-2.5 text-right text-cyber-blue">{att.action}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* MITRE ATT&CK Mappings & Social Engineering (LLM Card) */}
                  {emailResult.llm_analysis && (
                    <div className="glass-panel p-5 rounded-xl text-left space-y-4">
                      <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-1.5">
                        <Fingerprint className="w-4 h-4 text-cyber-blue" />
                        <span>Tactical Incident Report (MITRE ATT&CK)</span>
                      </h4>
                      
                      {/* Social Engineering Tactics */}
                      <div className="space-y-1.5">
                        <span className="text-[10px] font-mono text-slate-500 uppercase">Social Engineering Vectors</span>
                        <ul className="space-y-1">
                          {emailResult.llm_analysis.social_engineering_techniques.map((tech, i) => (
                            <li key={i} className="text-xs text-slate-350 list-disc list-inside font-sans">{tech}</li>
                          ))}
                        </ul>
                      </div>

                      {/* MITRE Mappings */}
                      <div className="space-y-2 pt-2 border-t border-slate-900">
                        <span className="text-[10px] font-mono text-slate-500 uppercase">MITRE ATT&CK Mapping Matrix</span>
                        <div className="grid grid-cols-1 gap-2">
                          {emailResult.llm_analysis.mitre_mappings.map((mapping, i) => (
                            <div key={i} className="p-3 bg-slate-950 border border-slate-900 rounded-lg flex gap-3">
                              <span className="font-mono text-xs font-bold text-cyber-red bg-cyber-red/5 border border-cyber-red/20 px-2 py-0.5 rounded h-fit shrink-0">
                                {mapping.id}
                              </span>
                              <div className="space-y-0.5">
                                <p className="text-xs font-bold text-slate-200">{mapping.name}</p>
                                <p className="text-[10px] text-slate-450 leading-relaxed">{mapping.description}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Indicators of Compromise */}
                      <div className="space-y-2 pt-2 border-t border-slate-900 font-mono">
                        <span className="text-[10px] text-slate-500 uppercase block">Extracted Indicators of Compromise (IOCs)</span>
                        <div className="flex flex-wrap gap-1.5">
                          {emailResult.llm_analysis.indicators_of_compromise.map((ioc, i) => (
                            <span key={i} className="text-[9px] bg-slate-900 text-slate-350 border border-slate-800 px-2 py-1 rounded truncate max-w-xs">
                              {ioc}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Risk Heatmap */}
                  <div className="glass-panel p-5 rounded-xl space-y-3">
                    <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2 flex justify-between items-center">
                      <span>Email Threat Heatmap</span>
                      <span className="text-[9px] text-cyber-red font-mono bg-cyber-red/10 px-2 py-0.5 rounded border border-cyber-red/20">
                        RED = DANGEROUS PHISHING WORD
                      </span>
                    </h4>
                    <div 
                      className="bg-slate-950 border border-slate-900 rounded-lg p-4 font-mono text-xs text-slate-350 leading-relaxed text-left whitespace-pre-wrap max-h-60 overflow-y-auto select-text"
                      dangerouslySetInnerHTML={{ __html: emailResult.highlighted_text }}
                    />
                  </div>
                </div>

                <div className="flex justify-end gap-3">
                  <button
                    onClick={() => {
                      setEmailResult(null);
                      setInputText('');
                      setFile(null);
                    }}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-lg border border-slate-700 transition-all duration-300 cursor-pointer"
                  >
                    SCAN NEW EMAIL
                  </button>
                  <button
                    onClick={() => handleExportPDF('email')}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyber-blue font-mono text-xs rounded-lg border border-slate-700 hover:border-cyber-blue transition-all duration-300 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    EXPORT REPORT AS PDF
                  </button>
                </div>
              </motion.div>
            )}

            {/* 4. URL Results */}
            {activeMode === 'url' && urlResult && (
              <motion.div
                key="url-result"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="space-y-4"
              >
                <div ref={urlReportRef} className="space-y-4 p-1.5 rounded-2xl bg-[#080b11]">
                  
                  {/* Shield Banner */}
                  <div className={`p-6 rounded-xl border relative overflow-hidden ${
                    urlResult.status === 'Dangerous' 
                      ? 'glass-panel-glow-red' 
                      : urlResult.status === 'Suspicious'
                      ? 'border-cyber-yellow/30 bg-slate-900/40 shadow-lg'
                      : 'glass-panel-glow-green'
                  }`}>
                    <div className="flex flex-col md:flex-row items-center justify-between gap-6 relative z-10">
                      <div className="flex items-center gap-4 text-left">
                        <div className={`p-3.5 rounded-2xl ${
                          urlResult.status === 'Dangerous' 
                            ? 'bg-cyber-red/10 text-cyber-red' 
                            : urlResult.status === 'Suspicious'
                            ? 'bg-cyber-yellow/10 text-cyber-yellow'
                            : 'bg-cyber-green/10 text-cyber-green'
                        }`}>
                          {urlResult.status === 'Safe' ? (
                            <ShieldCheck className="w-10 h-10" />
                          ) : urlResult.status === 'Suspicious' ? (
                            <AlertTriangle className="w-10 h-10" />
                          ) : (
                            <Shield className="w-10 h-10 animate-pulse-slow" />
                          )}
                        </div>
                        <div>
                          <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">URL Reputation Status</p>
                          <h2 className={`text-3xl font-extrabold mt-1 font-mono tracking-tight ${
                            urlResult.status === 'Dangerous' 
                              ? 'text-cyber-red' 
                              : urlResult.status === 'Suspicious'
                              ? 'text-cyber-yellow'
                              : 'text-cyber-green'
                          }`}>
                            {urlResult.status === 'Dangerous' ? 'DANGEROUS' : urlResult.status.toUpperCase()}
                          </h2>
                        </div>
                      </div>

                      {/* Score */}
                      <div className="text-center font-mono shrink-0">
                        <span className="text-xs text-slate-500 uppercase block">URL Risk Rating</span>
                        <span className={`text-3xl font-bold block mt-1 ${
                          urlResult.risk_score > 60 ? 'text-cyber-red' : urlResult.risk_score > 30 ? 'text-cyber-yellow' : 'text-cyber-green'
                        }`}>
                          {urlResult.risk_score}/100
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* URL Specific Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
                    
                    {/* Diagnosis & Reasons (Left 5 cols) */}
                    <div className="glass-panel p-5 rounded-xl space-y-3 md:col-span-5 text-left">
                      <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2">
                        Threat Diagnostic Details
                      </h4>
                      <div className="space-y-1.5 font-mono">
                        <span className="text-[10px] text-slate-500 uppercase">Target Domain</span>
                        <p className="text-xs font-semibold text-slate-200 truncate">{urlResult.domain}</p>
                      </div>
                      <div className="space-y-1.5 font-mono pt-1">
                        <span className="text-[10px] text-slate-500 uppercase">Vector Classification</span>
                        <p className={`text-xs font-bold ${
                          urlResult.status === 'Dangerous' ? 'text-cyber-red' : urlResult.status === 'Suspicious' ? 'text-cyber-yellow' : 'text-cyber-green'
                        }`}>
                          {urlResult.threat_type}
                        </p>
                      </div>
                      
                      <div className="pt-2 border-t border-slate-850 space-y-2">
                        <span className="text-[10px] font-mono text-slate-500 uppercase">Heuristic Flags Triggered:</span>
                        {urlResult.reasons.length === 0 ? (
                          <div className="flex items-center gap-1.5 text-xs text-cyber-green font-mono">
                            <CheckCircle className="w-3.5 h-3.5" />
                            <span>No security flags triggered</span>
                          </div>
                        ) : (
                          <ul className="space-y-1.5">
                            {urlResult.reasons.map((reason, i) => (
                              <li key={i} className="flex items-start gap-1.5 text-xs text-cyber-red font-mono">
                                <XCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                                <span>{reason}</span>
                              </li>
                            ))}
                          </ul>
                        )}
                      </div>
                    </div>

                    {/* Advice Card (Right 7 cols) */}
                    <div className="glass-panel p-5 rounded-xl md:col-span-7 flex flex-col justify-between text-left">
                      <div className="space-y-3">
                        <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                          <HelpCircle className="w-4 h-4 text-cyber-blue" />
                          <span>Actionable Security Advice</span>
                        </h4>
                        <div className={`p-4 rounded-lg border leading-relaxed text-xs ${
                          urlResult.status === 'Dangerous' 
                            ? 'bg-cyber-red/5 border-cyber-red/20 text-red-300' 
                            : urlResult.status === 'Suspicious'
                            ? 'bg-cyber-yellow/5 border-cyber-yellow/20 text-amber-200'
                            : 'bg-cyber-green/5 border-cyber-green/20 text-emerald-200'
                        }`}>
                          <p>{urlResult.advice}</p>
                        </div>
                      </div>

                      <div className="mt-4 p-2.5 bg-slate-900/50 rounded border border-slate-850 text-[10px] text-slate-500 font-mono leading-normal">
                        <strong>Security Tip:</strong> Cybercriminals often register look-alike domains (typosquatting) using slightly altered characters. Always double check the spelling of critical services.
                      </div>
                    </div>

                  </div>

                  {/* URL Mode Threat Intel Sub-Cards (VirusTotal & WHOIS) */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* VirusTotal Card */}
                    {urlResult.virustotal_results && (
                      <div className="glass-panel p-5 rounded-xl text-left space-y-2">
                        <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-1.5 flex items-center gap-1.5">
                          <Server className="w-4 h-4 text-cyber-blue" /> VirusTotal URL Registry
                        </h4>
                        <div className="grid grid-cols-2 gap-2 pt-1 font-mono text-xs">
                          <div className="bg-slate-950 p-2.5 rounded border border-slate-900 text-center">
                            <span className="text-[9px] text-slate-550 block">DETECTIONS</span>
                            <span className={`text-base font-bold ${urlResult.virustotal_results.malicious > 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
                              {urlResult.virustotal_results.malicious} / {urlResult.virustotal_results.malicious + urlResult.virustotal_results.harmless}
                            </span>
                          </div>
                          <div className="bg-slate-955 p-2.5 rounded border border-slate-900 text-center">
                            <span className="text-[9px] text-slate-550 block">REPUTATION</span>
                            <span className="text-base font-bold text-white">{urlResult.virustotal_results.reputation}</span>
                          </div>
                        </div>
                        <div className="flex justify-between text-[10px] font-mono text-slate-550 px-1">
                          <span>Community votes:</span>
                          <span className="text-cyber-green">+{urlResult.virustotal_results.community_votes_harmless} harmless</span>
                          <span className="text-cyber-red">-{urlResult.virustotal_results.community_votes_malicious} malicious</span>
                        </div>
                      </div>
                    )}

                    {/* WHOIS Card */}
                    {urlResult.whois_results && (
                      <div className="glass-panel p-5 rounded-xl text-left space-y-2">
                        <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-1.5 flex items-center gap-1.5">
                          <Globe className="w-4 h-4 text-cyber-blue" /> WHOIS Domain Metadata
                        </h4>
                        <div className="grid grid-cols-2 gap-2 text-[10px] font-mono text-slate-400">
                          <p className="truncate">Age: <span className="text-slate-200 font-bold">{urlResult.whois_results.domain_age_days ?? 'N/A'} days</span></p>
                          <p className="truncate">Country: <span className="text-slate-200 font-bold">{urlResult.whois_results.country}</span></p>
                          <p className="truncate">Registrar: <span className="text-slate-200 font-bold">{urlResult.whois_results.registrar}</span></p>
                          <p className="truncate">Registered: <span className="text-slate-200 font-bold">{urlResult.whois_results.registration_date}</span></p>
                        </div>
                        {urlResult.whois_results.is_new_domain && (
                          <div className="p-1.5 bg-cyber-red/10 border border-cyber-red/20 rounded text-[9px] font-mono text-cyber-red font-bold text-center animate-pulse">
                            ⚠️ NEW DOMAIN WARNING: REGISTERED &lt; 90 DAYS AGO!
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex justify-end gap-3">
                  <button
                    onClick={() => {
                      setUrlResult(null);
                      setInputUrl('');
                    }}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-lg border border-slate-700 transition-all duration-300 cursor-pointer"
                  >
                    SCAN NEW URL
                  </button>
                  <button
                    onClick={() => handleExportPDF('url')}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyber-blue font-mono text-xs rounded-lg border border-slate-700 hover:border-cyber-blue transition-all duration-300 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    EXPORT REPORT AS PDF
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
};
