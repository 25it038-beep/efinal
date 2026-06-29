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
  Flame,
  Key,
  DollarSign,
  Sparkles,
  RefreshCw,
  Link as LinkIcon,
  Globe,
  HelpCircle
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { API_URL, parseApiError, executeWithRetry } from '../config';
import confetti from 'canvas-confetti';
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
    if (file.size > 5 * 1024 * 1024) {
      setError('File size exceeds the 5MB limit.');
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

  const getIndicatorMetadata = (key: string) => {
    const meta: Record<string, { label: string, icon: any, desc: string }> = {
      urgent_language: { label: 'Urgent Language', icon: Flame, desc: 'Creates false sense of urgency or coercion' },
      fake_login: { label: 'Credential Harvesting', icon: Key, desc: 'Requests login or authentication details' },
      password_request: { label: 'Password Request', icon: Key, desc: 'Asks directly for sensitive passwords or pins' },
      banking_scam: { label: 'Banking Fraud', icon: DollarSign, desc: 'Includes wire transfer, bank account verification' },
      financial_fraud: { label: 'Financial Scam', icon: DollarSign, desc: 'References gift cards, lottery winnings, tax refunds' },
      crypto_scam: { label: 'Cryptocurrency Scam', icon: Sparkles, desc: 'Asks for wallet addresses, seed phrases, or crypto transfer' },
      suspicious_urls: { label: 'Suspicious URLs', icon: LinkIcon, desc: 'Contains IP-based, brand-hijacking, or unencrypted links' },
      spoofed_sender: { label: 'Spoofed Sender', icon: AlertTriangle, desc: 'Sender domain does not match links in the body' },
      grammar_issues: { label: 'Grammar/Tone Issues', icon: Info, desc: 'Contains excessive exclamation marks or capitalisation issues' },
      dangerous_attachments: { label: 'Dangerous Attachments', icon: FileText, desc: 'Includes executable files, scripts, or archive packages' }
    };
    return meta[key] || { label: key.replace('_', ' '), icon: Info, desc: 'Suspicious characteristic detected' };
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
            className={`px-4 py-1.5 rounded-lg font-mono text-xs tracking-wider transition-all duration-300 ${
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
            className={`px-4 py-1.5 rounded-lg font-mono text-xs tracking-wider transition-all duration-300 ${
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
        <div className="lg:col-span-5 space-y-4">
          <div className="glass-panel p-5 rounded-xl space-y-4">
            <h3 className="font-mono text-sm text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2">
              {activeMode === 'email' ? 'Email Input Stream' : 'Target URL Target'}
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
                      className="w-full h-64 bg-slate-950 border border-slate-880 focus:border-cyber-blue rounded-lg p-3 text-slate-200 placeholder-slate-600 focus:outline-none transition-all duration-300 font-mono text-xs resize-none"
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
                        <p className="text-[10px] text-slate-500 mt-2 font-mono">Accepts .txt or .eml files (Max 5MB)</p>
                      </div>
                    ) : (
                      <div className="flex items-center justify-between p-3 bg-slate-900 border border-slate-800 rounded-lg">
                        <div className="flex items-center gap-2.5">
                          <FileText className="w-5 h-5 text-cyber-blue" />
                          <div className="text-left">
                            <p className="text-xs font-medium text-slate-200 max-w-[180px] truncate">{file.name}</p>
                            <p className="text-[10px] text-slate-500 font-mono">{(file.size / 1024).toFixed(1)} KB</p>
                          </div>
                        </div>
                        <button 
                          onClick={removeFile}
                          className="p-1 text-slate-500 hover:text-cyber-red transition-colors"
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
              <div className="space-y-3">
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
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 focus:border-cyber-blue rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none transition-all duration-300 font-mono text-xs"
                  />
                </div>
                <div className="p-3 bg-slate-900/50 rounded-lg text-[10px] text-slate-500 font-mono leading-relaxed flex gap-2">
                  <Info className="w-3.5 h-3.5 text-cyber-blue shrink-0" />
                  <span>
                    Our URL engine performs deep reputation audit checking for typosquatting, brand hijacking, unencrypted protocols, raw IP hosting, and obfuscated subdomains.
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
              className={`w-full py-2.5 rounded-lg font-mono text-sm tracking-wide transition-all duration-300 ${
                loading
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold shadow-neon-blue border border-cyan-400/20 hover:border-cyan-400/40'
              }`}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  ANALYZING VECTOR TARGET...
                </span>
              ) : (
                activeMode === 'email' ? 'EXECUTE EMAIL SCAN' : 'ANALYZE URL REPUTATION'
              )}
            </button>
          </div>
        </div>

        {/* Right Column: Results Panel */}
        <div className="lg:col-span-7">
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
                  Paste a link in the left panel and click 'Analyze URL Reputation' to scan the host against security reputation blacklists.
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
                          <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">Diagnostic Result</p>
                          <h2 className={`text-3xl font-extrabold mt-1 font-mono tracking-tight ${
                            emailResult.classification === 'Phishing' 
                              ? 'text-cyber-red' 
                              : emailResult.classification === 'Suspicious'
                              ? 'text-cyber-yellow'
                              : 'text-cyber-green'
                          }`}>
                            {emailResult.classification.toUpperCase()}
                          </h2>
                        </div>
                      </div>

                      <div className="flex gap-6">
                        <div className="text-center font-mono">
                          <span className="text-xs text-slate-500 uppercase block">Confidence</span>
                          <span className="text-2xl font-bold text-white block mt-1">{emailResult.confidence_score}%</span>
                        </div>
                        <div className="text-center font-mono border-l border-slate-800 pl-6">
                          <span className="text-xs text-slate-500 uppercase block">Risk Score</span>
                          <span className={`text-2xl font-bold block mt-1 ${
                            emailResult.risk_score > 60 ? 'text-cyber-red' : emailResult.risk_score > 30 ? 'text-cyber-yellow' : 'text-cyber-green'
                          }`}>
                            {emailResult.risk_score}/100
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="mt-5 p-3 bg-slate-955 border border-slate-850 rounded-lg text-xs text-slate-300 leading-relaxed">
                      <p>{emailResult.explanation}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="glass-panel p-5 rounded-xl space-y-3">
                      <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2">
                        Threat Indicators Profile
                      </h4>
                      <div className="space-y-2.5 max-h-52 overflow-y-auto pr-1">
                        {Object.keys(emailResult.detected_indicators).map((key) => {
                          const isTriggered = emailResult.detected_indicators[key];
                          const meta = getIndicatorMetadata(key);
                          const Icon = meta.icon;
                          
                          return (
                            <div 
                              key={key} 
                              className={`flex items-center justify-between p-2 rounded-lg border text-xs transition-colors ${
                                isTriggered 
                                  ? 'bg-cyber-red/5 border-cyber-red/20 text-cyber-red' 
                                  : 'bg-slate-900/20 border-slate-850 text-slate-400'
                              }`}
                            >
                              <div className="flex items-center gap-2">
                                <Icon className={`w-3.5 h-3.5 ${isTriggered ? 'text-cyber-red' : 'text-slate-500'}`} />
                                <div className="text-left">
                                  <p className="font-medium">{meta.label}</p>
                                  <p className="text-[9px] text-slate-500 leading-tight">{meta.desc}</p>
                                </div>
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

                    <div className="glass-panel p-5 rounded-xl flex flex-col justify-between">
                      <div>
                        <h4 className="font-mono text-xs text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2">
                          AI Decision Keywords (XAI)
                        </h4>
                      </div>
                      <div className="h-44 mt-2">
                        {emailResult.xai_keywords.length === 0 ? (
                          <div className="flex items-center justify-center h-full text-xs text-slate-500 font-mono">
                            NO IMPORTANT KEYWORDS EXTRACTED
                          </div>
                        ) : (
                          <ResponsiveContainer width="100%" height="100%">
                            <BarChart 
                              data={emailResult.xai_keywords} 
                              layout="vertical" 
                              margin={{ top: 5, right: 10, left: -15, bottom: 5 }}
                            >
                              <XAxis type="number" stroke="#475569" fontSize={9} />
                              <YAxis dataKey="word" type="category" stroke="#94a3b8" fontSize={10} width={60} fontFamily="var(--font-mono)" />
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
                                {emailResult.xai_keywords.map((entry, index) => (
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
                      <div className="text-[9px] text-slate-500 font-mono text-center">
                        Relative word contribution weights to the AI classification
                      </div>
                    </div>
                  </div>

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
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-lg border border-slate-700 transition-all duration-300"
                  >
                    SCAN NEW EMAIL
                  </button>
                  <button
                    onClick={() => handleExportPDF('email')}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyber-blue font-mono text-xs rounded-lg border border-slate-700 hover:border-cyber-blue transition-all duration-300"
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
                </div>

                {/* Actions */}
                <div className="flex justify-end gap-3">
                  <button
                    onClick={() => {
                      setUrlResult(null);
                      setInputUrl('');
                    }}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-lg border border-slate-700 transition-all duration-300"
                  >
                    SCAN NEW URL
                  </button>
                  <button
                    onClick={() => handleExportPDF('url')}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyber-blue font-mono text-xs rounded-lg border border-slate-700 hover:border-cyber-blue transition-all duration-300"
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
