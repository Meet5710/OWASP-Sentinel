import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Globe,
  Share2,
  Copy,
  Check,
  ExternalLink,
  Power,
  RefreshCw,
  Key,
  Shield,
  X,
  AlertCircle,
  HelpCircle,
  Laptop,
} from 'lucide-react';
import { api } from '../services/api';
import type { NgrokStatus } from '../types/api';

interface NgrokModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const NgrokModal: React.FC<NgrokModalProps> = ({ isOpen, onClose }) => {
  const [status, setStatus] = useState<NgrokStatus | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [authtokenInput, setAuthtokenInput] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const fetchStatus = async () => {
    try {
      const res = await api.getNgrokStatus();
      setStatus(res);
      setActionError(null);
    } catch (err: any) {
      setActionError(err.message || 'Failed to check Ngrok status');
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchStatus();
      const interval = setInterval(fetchStatus, 4000);
      return () => clearInterval(interval);
    }
  }, [isOpen]);

  const shareableUrl = status?.public_url
    ? `${status.public_url}/app`
    : null;

  const handleCopy = () => {
    if (shareableUrl) {
      navigator.clipboard.writeText(shareableUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleStart = async () => {
    setIsLoading(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const res = await api.startNgrokTunnel(authtokenInput.trim() || undefined);
      setStatus(res);
      if (res.error) {
        setActionError(res.error);
      } else {
        setActionSuccess('Ngrok tunnel started! Public URL is live.');
      }
    } catch (err: any) {
      setActionError(err.message || 'Failed to launch Ngrok tunnel.');
    } finally {
      setIsLoading(false);
      fetchStatus();
    }
  };

  const handleStop = async () => {
    setIsLoading(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const res = await api.stopNgrokTunnel();
      setStatus(res);
      setActionSuccess('Ngrok tunnel disconnected.');
    } catch (err: any) {
      setActionError(err.message || 'Failed to stop Ngrok tunnel.');
    } finally {
      setIsLoading(false);
      fetchStatus();
    }
  };

  const handleSaveAuthtoken = async () => {
    if (!authtokenInput.trim()) return;
    setIsLoading(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      await api.setNgrokAuthtoken(authtokenInput.trim());
      setActionSuccess('Authtoken configured successfully!');
      setAuthtokenInput('');
      fetchStatus();
    } catch (err: any) {
      setActionError(err.message || 'Failed to save authtoken.');
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          transition={{ duration: 0.2 }}
          className="relative w-full max-w-xl liquid-glass rounded-3xl border border-white/15 p-6 shadow-2xl overflow-hidden"
        >
          {/* Header */}
          <div className="flex items-center justify-between pb-4 border-b border-white/10">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-2xl bg-gradient-to-br from-indigo-500 to-cyan-500 text-white shadow-lg shadow-cyan-500/20">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-900 dark:text-white tracking-tight flex items-center space-x-2">
                  <span>Share Platform via Ngrok</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 border border-cyan-500/40 font-semibold">
                    v3.39
                  </span>
                </h3>
                <p className="text-xs text-slate-400">
                  Allow anyone on any PC or phone to access OWASP Sentinel over the internet.
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-white/10 transition cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Feedback banners */}
          {actionError && (
            <div className="mt-4 p-3 rounded-xl bg-rose-500/20 border border-rose-500/40 text-rose-200 text-xs flex items-start space-x-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <div className="flex-1 break-words">{actionError}</div>
            </div>
          )}

          {actionSuccess && (
            <div className="mt-4 p-3 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-200 text-xs flex items-center space-x-2">
              <Check className="w-4 h-4 shrink-0" />
              <div className="flex-1">{actionSuccess}</div>
            </div>
          )}

          {/* Active Public URL Section */}
          <div className="mt-5 space-y-4">
            {status?.is_running && shareableUrl ? (
              <div className="liquid-glass border border-cyan-500/40 bg-gradient-to-br from-cyan-950/30 to-indigo-950/20 p-4.5 rounded-2xl space-y-3 shadow-lg shadow-cyan-500/10">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
                    <span className="text-xs font-bold uppercase tracking-wider text-emerald-300 font-mono">
                      Tunnel Online &amp; Live
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30">
                    HTTPS Secured
                  </span>
                </div>

                <div>
                  <label className="text-[11px] font-medium text-slate-300 block mb-1">
                    Sharable Public Web Dashboard Link:
                  </label>
                  <div className="flex items-center space-x-2">
                    <input
                      type="text"
                      readOnly
                      value={shareableUrl}
                      className="flex-1 bg-black/60 border border-cyan-500/40 rounded-xl px-3 py-2 text-xs font-mono text-cyan-200 select-all focus:outline-none focus:border-cyan-400"
                    />
                    <button
                      type="button"
                      onClick={handleCopy}
                      className="px-3.5 py-2 rounded-xl bg-cyan-500 text-black hover:bg-cyan-400 font-bold text-xs flex items-center space-x-1.5 transition cursor-pointer shadow-md shadow-cyan-500/30"
                      title="Copy Public Link"
                    >
                      {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copied ? 'Copied!' : 'Copy'}</span>
                    </button>
                    <a
                      href={shareableUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-2 rounded-xl bg-white/10 hover:bg-white/20 text-white transition flex items-center justify-center cursor-pointer border border-white/10"
                      title="Open in new browser window"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  </div>
                </div>

                <div className="p-2.5 rounded-xl bg-black/30 border border-white/5 text-[11px] text-slate-300 flex items-start space-x-2">
                  <Laptop className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <p>
                    Send this link to anyone. It opens directly in any browser on any PC or phone with zero setup needed!
                  </p>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <button
                    type="button"
                    onClick={handleStop}
                    disabled={isLoading}
                    className="px-3 py-1.5 rounded-xl bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-xs font-semibold flex items-center space-x-1.5 transition cursor-pointer disabled:opacity-50"
                  >
                    <Power className="w-3.5 h-3.5" />
                    <span>Stop Tunnel</span>
                  </button>

                  <button
                    type="button"
                    onClick={fetchStatus}
                    className="text-xs text-slate-400 hover:text-slate-200 flex items-center space-x-1 cursor-pointer font-mono"
                  >
                    <RefreshCw className="w-3 h-3" />
                    <span>Refresh status</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="liquid-glass border border-white/10 p-5 rounded-2xl space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-slate-500" />
                    <span className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
                      Tunnel Offline
                    </span>
                  </div>
                  <span className="text-[11px] text-slate-400 font-mono">Local Port: 8001</span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  Start the tunnel to expose the local Sentinel server over an encrypted public HTTPS domain.
                </p>

                {/* Authtoken Input if needed */}
                {!status?.authtoken_configured && (
                  <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-amber-300 flex items-center space-x-1.5">
                        <Key className="w-3.5 h-3.5" />
                        <span>Ngrok Free Authtoken Required</span>
                      </span>
                      <a
                        href="https://dashboard.ngrok.com/get-started/your-authtoken"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[11px] text-cyan-400 hover:underline flex items-center space-x-0.5"
                      >
                        <span>Get Token</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                    <div className="flex items-center space-x-2">
                      <input
                        type="password"
                        placeholder="Paste your ngrok authtoken here..."
                        value={authtokenInput}
                        onChange={(e) => setAuthtokenInput(e.target.value)}
                        className="flex-1 bg-white/90 dark:bg-black/60 border border-slate-300 dark:border-white/15 rounded-xl px-3 py-1.5 text-xs text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
                      />
                      <button
                        type="button"
                        onClick={handleSaveAuthtoken}
                        disabled={isLoading || !authtokenInput.trim()}
                        className="px-3 py-1.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-semibold text-xs transition cursor-pointer disabled:opacity-50"
                      >
                        Save
                      </button>
                    </div>
                  </div>
                )}

                <div className="pt-2 flex items-center justify-between">
                  <button
                    type="button"
                    onClick={handleStart}
                    disabled={isLoading}
                    className="px-4 py-2 rounded-xl bg-gradient-to-r from-indigo-500 to-cyan-500 hover:from-indigo-600 hover:to-cyan-600 text-white font-bold text-xs flex items-center space-x-2 transition cursor-pointer shadow-lg shadow-indigo-500/25 disabled:opacity-50"
                  >
                    {isLoading ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Share2 className="w-3.5 h-3.5" />
                    )}
                    <span>{isLoading ? 'Starting Tunnel...' : 'Start Public Tunnel'}</span>
                  </button>

                  <span className="text-[11px] text-slate-500 font-mono">
                    or run <code>start_ngrok.bat</code>
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Quick Terminal Tip */}
          <div className="mt-4 pt-3 border-t border-white/10 text-[11px] text-slate-400 font-mono flex items-center justify-between">
            <span>CLI Shortcut:</span>
            <code className="text-cyan-300 bg-white/5 px-2 py-0.5 rounded border border-white/10">
              python run_with_ngrok.py
            </code>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};

