import axios, { AxiosError } from 'axios';

const ENV_BASE_URLS = [
  import.meta.env.VITE_API_URL,
  import.meta.env.VITE_API_BASE_URL
].filter((value): value is string => Boolean(value));

const KNOWN_BACKEND_URLS = [
  'https://efinal-vpxh.onrender.com',
  'https://finalcheck-1.onrender.com'
].filter((value): value is string => Boolean(value));

const BROWSER_ORIGIN = typeof window !== 'undefined' ? window.location.origin : '';
const BASE_URLS = Array.from(new Set([...ENV_BASE_URLS, ...KNOWN_BACKEND_URLS, BROWSER_ORIGIN, '']))
  .filter((value): value is string => Boolean(value));

const DEFAULT_API_URL = BASE_URLS[0] || '';

// Prefer the environment override when provided; otherwise use the current host or a local backend.
export const API_URLS = BASE_URLS;
export const API_URL = DEFAULT_API_URL;

// Clean trailing slash if present
export const cleanApiUrl = (url: string) => url.endsWith('/') ? url.slice(0, -1) : url;

function getEndpointUrl(path: string, baseUrl: string) {
  const normalizedBase = baseUrl.replace(/\/$/, '');
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;

  if (!normalizedBase || normalizedBase === '/') {
    return normalizedPath;
  }

  return `${normalizedBase}${normalizedPath}`;
}

export function isOfflineError(error: unknown): boolean {
  if (!axios.isAxiosError(error)) {
    return true;
  }

  const axiosError = error as AxiosError;
  return !axiosError.response
    || axiosError.code === 'ECONNABORTED'
    || axiosError.code === 'ERR_NETWORK'
    || axiosError.code === 'ETIMEDOUT'
    || axiosError.message?.toLowerCase().includes('network');
}

export interface LocalPredictResponse {
  classification: string;
  confidence_score: number;
  risk_score: number;
  explanation: string;
  detected_indicators: Record<string, boolean>;
  highlighted_text: string;
  xai_keywords: Array<{ word: string; weight: number; type: string }>;
  id?: number;
  subject?: string;
  sender?: string;
  created_at?: string;
}

export function getOfflineEmailAnalysis(text: string, fileName?: string): LocalPredictResponse {
  const source = `${text || fileName || 'uploaded content'}`.toLowerCase();
  const suspiciousSignals = [
    /click/i,
    /urgent|immediately|act now|limited time/i,
    /verify|login|password|reset/i,
    /bank|invoice|pay/i,
    /free|winner|prize/i
  ];

  const matchedSignals = suspiciousSignals.filter((pattern) => pattern.test(source));
  const suspicious = matchedSignals.length >= 1;
  const classification = suspicious ? 'Suspicious' : 'Safe';
  const riskScore = suspicious ? 72 : 24;
  const confidence = suspicious ? 74 : 68;
  const explanation = suspicious
    ? 'The backend was unavailable, so this result uses a local heuristic scan. Common phishing cues such as urgency, credential requests, or payment pressure were detected.'
    : 'The backend was unavailable, so this result uses a local heuristic scan. No obvious phishing cues were detected in the supplied content.';

  return {
    classification,
    confidence_score: confidence,
    risk_score: riskScore,
    explanation,
    detected_indicators: {
      urgent_language: /urgent|immediately|act now|limited time/i.test(source),
      suspicious_urls: /http|https|login|verify/i.test(source),
      fake_login: /login|signin|verify/i.test(source),
      password_request: /password|reset/i.test(source),
      banking_scam: /bank|invoice|payment/i.test(source),
      financial_fraud: /pay|payment|invoice/i.test(source),
      crypto_scam: /crypto|wallet|coin/i.test(source),
      grammar_issues: false,
      spoofed_sender: false,
      dangerous_attachments: false
    },
    highlighted_text: text || fileName || 'Offline fallback analysis',
    xai_keywords: [
      { word: 'urgent', weight: 0.9, type: 'signal' },
      { word: 'password', weight: 0.85, type: 'signal' },
      { word: 'verify', weight: 0.8, type: 'signal' }
    ]
  };
}

export function getOfflineUrlAnalysis(url: string) {
  const lowered = url.toLowerCase();
  const suspicious = /login|signin|verify|secure|bank|pay|crypto|free/i.test(lowered);
  return {
    id: 0,
    url,
    domain: new URL(url).hostname.replace(/^www\./, ''),
    risk_score: suspicious ? 78 : 24,
    status: suspicious ? 'Suspicious' : 'Safe',
    reasons: suspicious
      ? ['The URL contains login-like or payment-related keywords.']
      : ['No obvious reputational risk cues were detected.'],
    threat_type: suspicious ? 'Phishing' : 'Low Risk',
    advice: suspicious
      ? 'Avoid entering credentials and verify the destination through a trusted channel.'
      : 'The URL looks benign based on the local heuristic check.',
    created_at: new Date().toISOString()
  };
}

export async function apiRequest<T>(path: string, options: { method?: 'get' | 'post'; data?: any; headers?: Record<string, string>; timeout?: number } = {}): Promise<T> {
  const method = options.method ?? 'get';
  let lastError: unknown;

  for (const baseUrl of API_URLS) {
    try {
      const response = await axios<T>({
        method,
        url: getEndpointUrl(path, baseUrl),
        data: options.data,
        headers: options.headers,
        timeout: options.timeout ?? 10000
      });
      return response.data;
    } catch (error) {
      lastError = error;
      if (axios.isAxiosError(error) && error.response && error.response.status >= 400 && error.response.status < 500) {
        throw error;
      }
    }
  }

  throw lastError ?? new Error('Unable to reach the security backend.');
}

/**
 * Parses axios or generic errors into human-readable, highly detailed strings.
 */
export function parseApiError(error: any): string {
  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError;

    if (!axiosError.response) {
      if (axiosError.code === 'ECONNABORTED') {
        return `Request Timeout: The request to the security engine timed out. Please try again.`;
      }
      return `Network Connectivity Error: The security server is currently unreachable. The app will try the next available backend and can also use a local fallback scan.`;
    }

    const status = axiosError.response.status;
    const data = axiosError.response.data as any;
    const serverMessage = data?.detail || data?.message;

    if (status === 401 || status === 403) {
      return `Access Denied (${status}): You do not have permission to access this threat resource.`;
    }
    if (status === 404) {
      return `Not Found (404): The requested threat scanning endpoint does not exist on the server.`;
    }
    if (status === 429) {
      return `Rate Limit Exceeded (429): You have sent too many scan requests. Please wait a moment before trying again.`;
    }
    if (status >= 500) {
      return `Internal Server Error (${status}): The security engine encountered an internal exception: ${serverMessage || 'Unknown error'}.`;
    }

    return serverMessage || `API Error (${status}): ${axiosError.message}`;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return 'An unexpected communication error occurred. Check the console for logs.';
}

/**
 * Executes an async API call with automatic retry logic (exponential backoff).
 */
export async function executeWithRetry<T>(
  fn: () => Promise<T>,
  retries = 2,
  delay = 1000
): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (retries > 0 && (isOfflineError(error) || (axios.isAxiosError(error) && (!error.response || error.response.status >= 500)))) {
      console.warn(`API call failed. Retrying in ${delay}ms... (${retries} retries left)`);
      await new Promise(resolve => setTimeout(resolve, delay));
      return executeWithRetry(fn, retries - 1, delay * 2);
    }
    throw error;
  }
}
