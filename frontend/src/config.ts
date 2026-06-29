import axios, { AxiosError } from 'axios';

// Dynamically use VITE_API_URL or fallback to the current window origin (useful for same-domain serving)
export const API_URL = import.meta.env.VITE_API_URL || window.location.origin;

// Clean trailing slash if present
export const cleanApiUrl = API_URL.endsWith('/') ? API_URL.slice(0, -1) : API_URL;

/**
 * Parses axios or generic errors into human-readable, highly detailed strings.
 */
export function parseApiError(error: any): string {
  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError;
    
    // Check if network error (no response)
    if (!axiosError.response) {
      if (axiosError.code === 'ECONNABORTED') {
        return `Request Timeout: The request to the security engine at ${cleanApiUrl} timed out. Please try again.`;
      }
      return `Network Connectivity Error: The security server at ${cleanApiUrl} is currently unreachable. Please verify your internet connection. Note: If the backend was sleeping, Render can take up to 50 seconds to boot.`;
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
    // Only retry on network errors or 5xx server errors
    if (retries > 0 && axios.isAxiosError(error) && (!error.response || error.response.status >= 500)) {
      console.warn(`API call failed. Retrying in ${delay}ms... (${retries} retries left)`);
      await new Promise(resolve => setTimeout(resolve, delay));
      return executeWithRetry(fn, retries - 1, delay * 2);
    }
    throw error;
  }
}
