/**
 * CyberFusion — Axios API Client
 *
 * Central Axios instance for all backend API calls.
 * Base URL is injected at build time via VITE_API_BASE_URL.
 * No secrets are ever included here.
 */
import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

const client = axios.create({
  baseURL: BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Response interceptor — normalise errors without leaking internals
client.interceptors.response.use(
  (response) => response,
  (error) => {
    const message =
      error.response?.data?.message ||
      (error.code === 'ECONNABORTED' ? 'Request timed out' : 'Unable to reach intelligence services');
    return Promise.reject(new Error(message));
  },
);

export default client;
