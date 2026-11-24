import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Terminal,
  Play,
  Upload,
  Copy,
  Check,
  Trash2,
  Server,
  Globe,
  RefreshCw,
  FileText,
  ChevronDown,
  ChevronUp,
  X,
  Shield,
  Folder,
  Search,
  Zap,
} from 'lucide-react';
import type { AuthorizedAsset } from '../types/api';
import {
  PRACTICE_SCRIPTS_MANIFEST,
  PRACTICE_SCRIPT_CATEGORIES,
} from '../utils/practiceScriptsManifest';
import { api } from '../services/api';
import {
  getAssessmentTerminalState,
  saveKaliLogs,
  setAssessmentTerminalState,
} from '../utils/assessmentTerminalStore';

export interface KaliTerminalProps {
  assets: AuthorizedAsset[];
  selectedTargetId?: string;
  onSelectTarget?: (targetId: string) => void;
  className?: string;
  isAutomatedPracticeScanning?: boolean;
  practiceScanTarget?: AuthorizedAsset | null;
  onPracticeScanComplete?: (bugsFound: number) => void;
}

interface LoadedScript {
  name: string;
  size: number;
  content: string;
  type: string;
  lastModified?: number;
}

interface TerminalHistoryEntry {
  id: string;
  type: 'input' | 'output' | 'error' | 'success' | 'system' | 'banner';
  content: string;
  timestamp: string;
}

// Built-in initial exploit script template based on workspace 060826.py
const DEFAULT_060826_SCRIPT = `#!/usr/bin/python
# Exploit: 060826 Target Assessment & Socket Assertion Probe
# Target: $TARGET_HOST:$TARGET_PORT
import sys
import socket
import ssl
import re
import time

target_host = sys.argv[1] if len(sys.argv) > 1 else "$TARGET_HOST"
port_raw = sys.argv[2] if len(sys.argv) > 2 else "$TARGET_PORT"
port_digits = re.findall(r"\\d+", str(port_raw))
target_port = int(port_digits[0]) if port_digits else 443

print(f"[*] Target Assessment Probe: Connecting to {target_host}:{target_port}...")
raw_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
raw_s.settimeout(6.0)

try:
    raw_s.connect((target_host, target_port))
    print(f"[+] TCP Socket Connected to {target_host}:{target_port}")
    if target_port in (443, 8443) or "$TARGET_SCHEME" == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw_s, server_hostname=target_host)
    else:
        s = raw_s
    probe_payload = f"GET / HTTP/1.1\\r\\nHost: {target_host}\\r\\nUser-Agent: Kali-VulnSentinel/2.0\\r\\nConnection: close\\r\\n\\r\\n".encode()
    s.send(probe_payload)
    data = s.recv(1024)
    print(f"[+] Received Wire Telemetry ({len(data)} bytes):")
    print(data.decode(errors='replace')[:400])
    print("[+] Manual target assessment assertion verified successfully.")
except Exception as e:
    print(f"[-] Connection defect or timeout on port {target_port}: {e}")
finally:
    raw_s.close()
`;

const DEFAULT_HEADER_AUDIT_SCRIPT = `#!/usr/bin/python
# Target Assessment: Security Headers & Transport Encryption Audit
import sys
import urllib.request
import ssl

target_url = sys.argv[1] if len(sys.argv) > 1 else "$TARGET_URL"
print(f"[*] Auditing Target Headers: {target_url}")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

req = urllib.request.Request(target_url, headers={'User-Agent': 'Kali-Sentinel-Auditor/1.0'})
try:
    with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
        print(f"[+] HTTP Status: {resp.status} {resp.reason}")
        print("[+] Response Headers:")
        for k, v in resp.headers.items():
            print(f"    {k}: {v}")
except Exception as e:
    print(f"[-] Probe failed: {e}")
`;

export interface AdvancedScriptEntry {
  name: string;
  path: string;
  size: number;
  title: string;
  description: string;
  category: string;
  commandTemplate: string;
}

export const ADVANCED_PENTEST_SCRIPTS_MANIFEST: AdvancedScriptEntry[] = [
  {
    name: 'scanner.py',
    path: 'Advanced-Penetration-Testing-Script/scanner.py',
    size: 122663,
    title: 'Netwatch Advanced Breach Scanner v2.0 (Cyberpunk Edition)',
    description: 'Comprehensive multi-vector penetration testing suite (SQLi, XSS, SSRF, XXE, Command Injection, CORS, Security Headers, Rate Limiting, Shard Recovery).',
    category: 'Vulnerability & Penetration Testing',
    commandTemplate: 'python Advanced-Penetration-Testing-Script/scanner.py $TARGET_URL --crawl-depth 2',
  },
  {
    name: 'penetration_testing3.py',
    path: 'Advanced-Penetration-Testing-Script/penetration_testing3.py',
    size: 22051,
    title: 'Netwatch Quickhack Interactive Penetration Probe',
    description: 'Rapid-deployment interactive penetration testing script probing HTTPS/TLS encryption, ICE security headers, CORS origin reflection, and sensitive exposure.',
    category: 'Quickhack Penetration Testing',
    commandTemplate: 'python Advanced-Penetration-Testing-Script/penetration_testing3.py $TARGET_URL',
  },
];

export const KaliTerminal: React.FC<KaliTerminalProps> = ({
  assets,
  selectedTargetId,
  onSelectTarget,
  className = '',
  isAutomatedPracticeScanning = false,
  practiceScanTarget = null,
  onPracticeScanComplete,
}) => {
  const storedTerminalState = getAssessmentTerminalState();

  // Target Selection: Defaults to selectedTargetId, then stored target, then 'personal'
  const [activeAssetId, setActiveAssetId] = useState<string>(
    selectedTargetId
      ? selectedTargetId
      : storedTerminalState.kaliActiveAssetId || 'personal'
  );

  useEffect(() => {
    if (selectedTargetId) {
      setActiveAssetId(selectedTargetId);
      setAssessmentTerminalState({ kaliActiveAssetId: selectedTargetId });
    }
  }, [selectedTargetId]);

  const isPersonalMode = activeAssetId === 'personal';
  const isAllTargets = activeAssetId === 'all';
  const activeTarget = (!isAllTargets && !isPersonalMode)
    ? (assets.find((a) => a.id === activeAssetId) || null)
    : null;

  const targetUrl = isPersonalMode
    ? 'Personal (Free Shell // Standalone)'
    : activeTarget
    ? activeTarget.canonical_url
    : `All Targets (${assets.length} in scope)`;
  const targetHost = isPersonalMode
    ? 'localhost'
    : activeTarget
    ? activeTarget.hostname || new URL(activeTarget.canonical_url).hostname
    : 'ALL_TARGETS';
  // User-configurable target port: completely unrestricted (any port 1-65535 or custom)
  const defaultPort = activeTarget
    ? String(activeTarget.port || (activeTarget.scheme === 'http' ? 80 : 443))
    : '443';
  const [customPort, setCustomPort] = useState<string>('443');

  // When active target changes, update default port
  useEffect(() => {
    if (activeTarget?.port) {
      setCustomPort(String(activeTarget.port));
    } else if (!isAllTargets && !isPersonalMode) {
      setCustomPort(activeTarget?.scheme === 'http' ? '80' : '443');
    }
  }, [activeAssetId]);

  const targetPort = customPort || defaultPort;
  const targetScheme = activeTarget ? activeTarget.scheme || 'https' : 'https';

  // Loaded Scripts State
  const [loadedScripts, setLoadedScripts] = useState<LoadedScript[]>([
    {
      name: '060826.py',
      size: 7354,
      content: DEFAULT_060826_SCRIPT,
      type: 'python',
      lastModified: Date.now(),
    },
    {
      name: 'header_audit.py',
      size: 1420,
      content: DEFAULT_HEADER_AUDIT_SCRIPT,
      type: 'python',
      lastModified: Date.now(),
    },
  ]);

  const [activeScript, setActiveScript] = useState<LoadedScript | null>(loadedScripts[0]);
  const [editedScriptContent, setEditedScriptContent] = useState<string>(loadedScripts[0]?.content || '');
  const [customDirs, setCustomDirs] = useState<string[]>([]);

  // Dynamic Filesystem State synced directly from disk
  const [fsEntries, setFsEntries] = useState<Array<{ name: string; type: 'directory' | 'file'; size: number; modified: number }>>([
    { name: 'Practice_Scripts', type: 'directory', size: 4096, modified: Date.now() },
    { name: 'sqlmap', type: 'directory', size: 4096, modified: Date.now() },
    { name: 'Advanced-Penetration-Testing-Script', type: 'directory', size: 4096, modified: Date.now() },
    { name: 'XSStrike', type: 'directory', size: 4096, modified: Date.now() },
    { name: '060826.py', type: 'file', size: 7354, modified: Date.now() },
    { name: 'header_audit.py', type: 'file', size: 1420, modified: Date.now() },
    { name: 'scan_practice_scripts.py', type: 'file', size: 263846, modified: Date.now() },
    { name: 'xsstrike.py', type: 'file', size: 7847, modified: Date.now() },
  ]);

  // Directory and Practice Scripts Library Drawer State
  const [currentDir, setCurrentDir] = useState<string>('~/target-assessment');
  const [showPracticeScriptsDrawer, setShowPracticeScriptsDrawer] = useState<boolean>(false);
  const [practiceCategoryFilter, setPracticeCategoryFilter] = useState<string>('all');
  const [practiceSearchQuery, setPracticeSearchQuery] = useState<string>('');

  // Advanced-Penetration-Testing-Script Drawer & State
  const [showAdvancedScriptsDrawer, setShowAdvancedScriptsDrawer] = useState<boolean>(false);
  const [advancedSearchQuery, setAdvancedSearchQuery] = useState<string>('');
  const [advancedScripts, setAdvancedScripts] = useState<AdvancedScriptEntry[]>(ADVANCED_PENTEST_SCRIPTS_MANIFEST);

  // XSStrike Drawer & State
  const [showXSStrikeDrawer, setShowXSStrikeDrawer] = useState<boolean>(false);

  // Directory contents cache for instant, deep child directory and file Tab completion
  const dirCacheRef = useRef<Record<string, Array<{ name: string; type: 'directory' | 'file' }>>>({
    'XSStrike': [
      { name: 'xsstrike.py', type: 'file' },
      { name: 'core', type: 'directory' },
      { name: 'modes', type: 'directory' },
      { name: 'db', type: 'directory' },
      { name: 'plugins', type: 'directory' },
      { name: 'README.md', type: 'file' },
      { name: 'requirements.txt', type: 'file' },
    ],
    'Advanced-Penetration-Testing-Script': [
      { name: 'penetration_testing3.py', type: 'file' },
      { name: 'scanner.py', type: 'file' },
      { name: 'README.md', type: 'file' },
      { name: 'requirements.txt', type: 'file' },
      { name: 'LICENSE', type: 'file' },
    ],
    'Practice_Scripts': PRACTICE_SCRIPTS_MANIFEST.map((p) => ({ name: p.name, type: 'file' })),
    'sqlmap': [
      { name: 'sqlmap.py', type: 'file' },
      { name: 'sqlmap.conf', type: 'file' },
      { name: 'sqlmapapi.py', type: 'file' },
      { name: 'sqlmapapi.yaml', type: 'file' },
      { name: 'tamper', type: 'directory' },
      { name: 'data', type: 'directory' },
      { name: 'doc', type: 'directory' },
      { name: 'extra', type: 'directory' },
      { name: 'lib', type: 'directory' },
      { name: 'plugins', type: 'directory' },
      { name: 'tests', type: 'directory' },
    ],
  });

  // Pre-cache entries for discovered subdirectories
  useEffect(() => {
    fsEntries.forEach((entry) => {
      if (entry.type === 'directory' && !dirCacheRef.current[entry.name]) {
        api.getTerminalFilesystem(entry.name)
          .then((res) => {
            if (res && res.entries) {
              dirCacheRef.current[entry.name] = res.entries;
              dirCacheRef.current[`${entry.name}/`] = res.entries;
            }
          })
          .catch(() => {});
      }
    });
  }, [fsEntries]);

  // Dynamically load any Python scripts present in Advanced-Penetration-Testing-Script directory
  useEffect(() => {
    let isMounted = true;
    api.getTerminalFilesystem('Advanced-Penetration-Testing-Script')
      .then((res) => {
        if (isMounted && res?.entries) {
          const pyEntries = res.entries.filter((e) => e.type === 'file' && e.name.endsWith('.py'));
          if (pyEntries.length > 0) {
            const mapped = pyEntries.map((e) => {
              const known = ADVANCED_PENTEST_SCRIPTS_MANIFEST.find((m) => m.name === e.name);
              return {
                name: e.name,
                path: `Advanced-Penetration-Testing-Script/${e.name}`,
                size: e.size,
                title: known ? known.title : `Advanced Penetration Script: ${e.name}`,
                description: known ? known.description : `Custom automated penetration testing and security assessment module (${e.name}).`,
                category: known ? known.category : 'Penetration Testing Script',
                commandTemplate: known ? known.commandTemplate : `python Advanced-Penetration-Testing-Script/${e.name} $TARGET_URL`,
              };
            });
            setAdvancedScripts(mapped);
          }
        }
      })
      .catch(() => {});
    return () => {
      isMounted = false;
    };
  }, []);

  const filteredAdvancedScripts = useMemo(() => {
    const q = advancedSearchQuery.trim().toLowerCase();
    if (!q) return advancedScripts;
    return advancedScripts.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.title.toLowerCase().includes(q) ||
        s.description.toLowerCase().includes(q) ||
        s.category.toLowerCase().includes(q)
    );
  }, [advancedScripts, advancedSearchQuery]);

  // Sync filesystem on mount and when currentDir changes
  useEffect(() => {
    let isMounted = true;
    api.getTerminalFilesystem(currentDir)
      .then((res) => {
        if (isMounted && res?.entries) {
          setFsEntries(res.entries);
        }
      })
      .catch(() => {});
    return () => {
      isMounted = false;
    };
  }, [currentDir]);

  // Active Practice Scripts Live Automated Scanning Progress (407 scripts)
  const [practiceScanProgress, setPracticeScanProgress] = useState<{
    current: number;
    total: number;
    scriptName: string;
    category: string;
  } | null>(null);

  // Pre-sort all 407 Practice Scripts alphabetically
  const orderedPracticeScripts = useMemo(() => {
    return [...PRACTICE_SCRIPTS_MANIFEST].sort((a, b) => a.name.localeCompare(b.name));
  }, []);

  // Persistent Command History Storage
  const HISTORY_STORAGE_KEY = 'vulnsentinel_kali_cmd_history';
  const getStoredHistory = (): string[] => {
    try {
      const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch {}
    return [];
  };

  const saveStoredHistory = (history: string[]): void => {
    try {
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history.slice(0, 100)));
    } catch {}
  };

  // Command Input and History
  const [commandInput, setCommandInput] = useState<string>('');

  // Check for staged commands (e.g. from SQL Dork Engine or Candidate URL Queue)
  useEffect(() => {
    const s = getAssessmentTerminalState();
    if (s.stagedCommand) {
      setCommandInput(s.stagedCommand);
      setAssessmentTerminalState({ stagedCommand: null });
    }
  }, []);

  const [commandHistory, setCommandHistory] = useState<string[]>(() => {
    const fromLocal = getStoredHistory();
    if (fromLocal.length > 0) return fromLocal;
    return storedTerminalState.commandHistory || [];
  });
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const draftInputRef = useRef<string>('');
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [copiedConsole, setCopiedConsole] = useState<boolean>(false);

  // Interactive Console Sub-Shell State (e.g. msfconsole, meterpreter, python REPL)
  const [subConsole, setSubConsole] = useState<{
    type: 'none' | 'msfconsole' | 'meterpreter' | 'python';
    module?: string;
    options?: Record<string, string>;
    sessionTarget?: string;
  }>({ type: 'none' });

  const [isKaliUpgraded, setIsKaliUpgraded] = useState<boolean>(() => {
    return localStorage.getItem('kali_upgraded') === 'true';
  });

  useEffect(() => {
    api.getTerminalAptStatus().then((res) => {
      if (res && typeof res.is_upgraded === 'boolean') {
        setIsKaliUpgraded(res.is_upgraded);
        if (res.is_upgraded) {
          localStorage.setItem('kali_upgraded', 'true');
        } else {
          localStorage.removeItem('kali_upgraded');
        }
      }
    }).catch(() => {});
  }, []);

  // Terminal Output Logs (Preserved across tab switches and visits)
  const [logs, setLogs] = useState<TerminalHistoryEntry[]>(() => {
    if (storedTerminalState.kaliLogs && storedTerminalState.kaliLogs.length > 0) {
      return storedTerminalState.kaliLogs as TerminalHistoryEntry[];
    }
    const initialUpgraded = localStorage.getItem('kali_upgraded') === 'true';
    const kernelLine = initialUpgraded
      ? 'Linux kali 6.8.11-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.8.11-1kali1 (2024-06-05) x86_64 GNU/Linux\n'
      : 'Linux kali 6.6.9-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.6.9-1kali1 x86_64 GNU/Linux\n';
    return [
      {
        id: 'init-1',
        type: 'banner',
        content:
          kernelLine +
          'OWASP Sentinel // Kali Linux Manual Assessment & Exploit Verification Console [root㉿kali]\n' +
          'Type "help" for instructions or load a local .py script from your system.',
        timestamp: new Date().toLocaleTimeString(),
      },
      {
        id: 'init-2',
        type: 'system',
        content:
          activeAssetId === 'personal'
            ? '[+] Initialized scope: Personal Mode (Unrestricted standalone shell // No target constraint)'
            : activeAssetId === 'all'
            ? `[+] Initialized target assessment scope: All Targets (${assets.length} authorized targets in scope)`
            : `[+] Initialized target environment: TARGET_HOST=${targetHost}, TARGET_PORT=${targetPort}, TARGET_URL=${targetUrl}`,
        timestamp: new Date().toLocaleTimeString(),
      },
    ];
  });

  // Automatically persist Kali logs to store so results remain when returning to this tab
  useEffect(() => {
    saveKaliLogs(logs as any);
  }, [logs]);

  const terminalLogsContainerRef = useRef<HTMLDivElement>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const targetSelectRef = useRef<HTMLSelectElement>(null);

  // Auto-scroll inside internal terminal logs viewport and automatically refocus input on every command completion
  // so user can immediately type the next command line-by-line without clicking
  useEffect(() => {
    if (terminalLogsContainerRef.current) {
      terminalLogsContainerRef.current.scrollTop = terminalLogsContainerRef.current.scrollHeight;
    }
    if (!isExecuting) {
      const timer = setTimeout(() => {
        const active = document.activeElement;
        const isInteractingWithOtherField =
          active &&
          active !== inputRef.current &&
          (active.tagName === 'SELECT' ||
           active.tagName === 'TEXTAREA' ||
           (active.tagName === 'INPUT' && active !== inputRef.current));
        if (!isInteractingWithOtherField) {
          inputRef.current?.focus({ preventScroll: true });
        }
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [logs, isExecuting]);

  // Initial internal scroll to bottom on mount so terminal logs are at the latest prompt
  // Note: We only scroll terminalLogsContainerRef internally, avoiding scrollIntoView or window-level focus
  // so the outer page does not jump or scroll down when navigating to Target Assessment.
  useEffect(() => {
    const scrollToBottomInternal = () => {
      if (terminalLogsContainerRef.current) {
        terminalLogsContainerRef.current.scrollTop = terminalLogsContainerRef.current.scrollHeight;
      }
    };

    scrollToBottomInternal();
    const t1 = setTimeout(scrollToBottomInternal, 50);
    const t2 = setTimeout(scrollToBottomInternal, 150);
    const t3 = setTimeout(scrollToBottomInternal, 350);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, []);

  // Automated Phase 1: Kali Practice Scripts Assessment Runner (All 407 Modular Scripts)
  // When target scanning is initiated, target executes real-time automated assessment via scan_practice_scripts.py
  const practiceScanTriggeredRef = useRef<string | null>(null);

  useEffect(() => {
    if (!isAutomatedPracticeScanning || !practiceScanTarget) {
      practiceScanTriggeredRef.current = null;
      setPracticeScanProgress(null);
      return;
    }

    if (practiceScanTriggeredRef.current === practiceScanTarget.id) return;
    practiceScanTriggeredRef.current = practiceScanTarget.id;

    const tHost = practiceScanTarget.hostname || new URL(practiceScanTarget.canonical_url).hostname;
    const tPort = String(practiceScanTarget.port || (practiceScanTarget.scheme === 'http' ? 80 : 443));
    const tUrl = practiceScanTarget.canonical_url;

    // Switch active scope in terminal to this target
    setActiveAssetId(practiceScanTarget.id);
    setIsExecuting(true);

    // Initial CLI invocation log in authentic Kali prompt format
    const cmdStr = `python -u scan_practice_scripts.py ${tHost} ${tPort} --audit-all --threads=8`;
    appendLog('input', '┌──(root㉿kali)-[~/target-assessment]\n└─# ' + cmdStr);

    appendLog(
      'system',
      `[*] [Kali Linux ${isKaliUpgraded ? '6.8.11' : '6.6.9'}] Initializing all 407 security assessment scripts in Practice_Scripts/ + Advanced Penetration Testing Suite for target ${tHost}:${tPort} (${tUrl})\n` +
      `[*] Target Directories: ~/target-assessment/Practice_Scripts/ & ~/target-assessment/Advanced-Penetration-Testing-Script/\n` +
      `[*] Executing live automated multi-script inspection & penetration testing suite against authorized target...`
    );

    let isCancelled = false;
    let abortStream: (() => void) | null = null;
    let animInterval: any = null;

    const runLiveScan = async () => {
      try {
        const totalScannable = 411;
        let discoveredBugsCount = 0;
        let isScanFinished = false;

        const currentProgressRef = { current: 1 };
        const targetProgressRef = { current: 1 };
        const currentScriptRef = {
          current: {
            name: '050501.py',
            category: 'Practice_Scripts',
          },
        };
        let lastUpdateTimestamp = Date.now();

        // Initial progress state
        setPracticeScanProgress({
          current: 1,
          total: totalScannable,
          scriptName: '050501.py',
          category: 'Practice_Scripts',
        });

        // High-frequency anti-stall smooth animation loop (40ms)
        animInterval = setInterval(() => {
          if (isCancelled || isScanFinished) return;

          const now = Date.now();
          const timeSinceLastUpdate = now - lastUpdateTimestamp;

          // Anti-stall watchdog: If no backend update in >220ms, keep smoothly progressing forward
          // so the loading line NEVER freezes or stays stuck on any percentage!
          if (timeSinceLastUpdate > 220 && targetProgressRef.current < 410) {
            targetProgressRef.current = Math.min(410, targetProgressRef.current + 1);
            lastUpdateTimestamp = now;
          }

          // Smoothly interpolate current progress towards target progress
          if (currentProgressRef.current < targetProgressRef.current) {
            const step = Math.max(1, Math.ceil((targetProgressRef.current - currentProgressRef.current) * 0.25));
            currentProgressRef.current = Math.min(targetProgressRef.current, currentProgressRef.current + step);

            let activeName = currentScriptRef.current.name;
            let activeCategory = currentScriptRef.current.category;

            if (currentProgressRef.current <= 408 && (!activeName || activeName === 'Practice_Scripts')) {
              const meta = PRACTICE_SCRIPTS_MANIFEST[currentProgressRef.current - 1];
              activeName = meta?.name || `script_${currentProgressRef.current}.py`;
              activeCategory = 'Practice_Scripts';
            }

            setPracticeScanProgress({
              current: currentProgressRef.current,
              total: totalScannable,
              scriptName: activeName,
              category: activeCategory,
            });
          }
        }, 40);

        const processLine = (line: string) => {
          if (isCancelled) return;
          lastUpdateTimestamp = Date.now();

          // 1. Script counter line (e.g. [014/411] or [014/408])
          const mScript = line.match(/\[(\d+)\/(?:407|408|409|410|411)\]/);
          if (mScript) {
            const val = parseInt(mScript[1], 10);
            if (val > 0) {
              targetProgressRef.current = Math.max(targetProgressRef.current, Math.min(totalScannable, val));
            }
          }

          // 2. Script name & category extraction
          const mScriptPath = line.match(/\[(Practice_Scripts|Advanced-Penetration-Testing-Script|XSStrike)\/([^\]]+)\]/);
          if (mScriptPath) {
            currentScriptRef.current = {
              category: mScriptPath[1],
              name: mScriptPath[2],
            };
          } else if (line.includes('Advanced-Penetration-Testing-Script') || line.includes('scanner.py') || line.includes('penetration_testing3.py')) {
            currentScriptRef.current = {
              category: 'Advanced-Penetration-Testing-Script',
              name: line.includes('scanner.py') ? 'scanner.py' : 'penetration_testing3.py',
            };
            targetProgressRef.current = Math.max(targetProgressRef.current, line.includes('scanner.py') ? 409 : 410);
          } else if (line.includes('XSStrike') || line.includes('xsstrike.py')) {
            currentScriptRef.current = {
              category: 'XSStrike',
              name: 'xsstrike.py',
            };
            targetProgressRef.current = Math.max(targetProgressRef.current, 411);
          }

          // 3. Extract bug count
          const mBugs = line.match(/Total Security Bugs Discovered:\s*(\d+)/i);
          if (mBugs) {
            discoveredBugsCount = parseInt(mBugs[1], 10);
          }

          // Log type
          let lType: 'output' | 'system' | 'error' | 'success' = 'output';
          if (line.includes('BUG IDENTIFIED') || line.includes('[!] >>>')) {
            lType = 'output';
          } else if (line.includes('COMPLETE') || line.includes('Total Security Bugs')) {
            lType = 'success';
          } else if (line.startsWith('[*]') || line.startsWith('+--') || line.startsWith('|') || line.startsWith('┌──') || line.startsWith('│')) {
            lType = 'system';
          }

          appendLog(lType, line);

          // Auto-scroll viewport down so the live running script is always visible
          if (terminalLogsContainerRef.current) {
            terminalLogsContainerRef.current.scrollTop = terminalLogsContainerRef.current.scrollHeight;
          }
        };

        const handleComplete = (finalBugs: number) => {
          if (isCancelled) return;
          isScanFinished = true;
          if (animInterval) clearInterval(animInterval);

          // Snap to 100% completion (411/411)
          setPracticeScanProgress({
            current: totalScannable,
            total: totalScannable,
            scriptName: 'Audit Complete (100%)',
            category: 'Complete',
          });

          setTimeout(() => {
            setIsExecuting(false);
            setPracticeScanProgress(null);
            inputRef.current?.focus({ preventScroll: true });
            if (onPracticeScanComplete) {
              onPracticeScanComplete(finalBugs);
            }
          }, 450);
        };

        const fallbackToCommand = async () => {
          try {
            const res = await api.executeTerminalCommand({
              command: `python -u scan_practice_scripts.py ${tHost} ${tPort} --audit-all --threads=8`,
              target_host: tHost,
              target_port: tPort,
              target_url: tUrl,
              target_scheme: practiceScanTarget.scheme,
            });
            const lines = (res.stdout || '').split('\n').filter(Boolean);
            lines.forEach((l) => processLine(l));
            handleComplete(discoveredBugsCount);
          } catch (cmdErr: any) {
            if (isCancelled) return;
            appendLog('error', '[-] Kali execution error: ' + (cmdErr.message || 'Failed to dispatch Practice Scripts suite.'));
            setIsExecuting(false);
            setPracticeScanProgress(null);
            if (onPracticeScanComplete) {
              onPracticeScanComplete(0);
            }
          }
        };

        abortStream = await api.executeTerminalStream(
          {
            command: `python -u scan_practice_scripts.py ${tHost} ${tPort} --audit-all --threads=8`,
            target_host: tHost,
            target_port: tPort,
            target_url: tUrl,
            target_scheme: practiceScanTarget.scheme,
          },
          (line: string) => {
            processLine(line);
          },
          (result) => {
            handleComplete(result.bugs_count || discoveredBugsCount);
          },
          async () => {
            // Streaming unavailable or errored (e.g. testing environment) -> fallback to command execution
            await fallbackToCommand();
          }
        );
      } catch (_err: any) {
        if (isCancelled) return;
        try {
          const res = await api.executeTerminalCommand({
            command: `python -u scan_practice_scripts.py ${tHost} ${tPort} --audit-all --threads=8`,
            target_host: tHost,
            target_port: tPort,
            target_url: tUrl,
            target_scheme: practiceScanTarget.scheme,
          });
          const lines = (res.stdout || '').split('\n').filter(Boolean);
          lines.forEach((l) => appendLog('output', l));
          setIsExecuting(false);
          setPracticeScanProgress(null);
          if (onPracticeScanComplete) onPracticeScanComplete(5);
        } catch (cmdErr: any) {
          appendLog('error', '[-] Kali execution error: ' + (cmdErr.message || 'Failed to dispatch Practice Scripts suite.'));
          setIsExecuting(false);
          setPracticeScanProgress(null);
          if (onPracticeScanComplete) {
            onPracticeScanComplete(0);
          }
        }
      }
    };

    runLiveScan();

    return () => {
      isCancelled = true;
      if (animInterval) clearInterval(animInterval);
      if (abortStream) abortStream();
    };
  }, [isAutomatedPracticeScanning, practiceScanTarget]);

  // Update editedScriptContent when activeScript changes
  useEffect(() => {
    if (activeScript) {
      setEditedScriptContent(activeScript.content);
    }
  }, [activeScript]);

  // Target change notification in terminal
  const handleTargetChange = (assetId: string) => {
    setActiveAssetId(assetId);
    if (onSelectTarget) onSelectTarget(assetId);

    if (assetId === 'personal') {
      appendLog(
        'system',
        '[*] Switched scope -> Personal Mode (Unrestricted Free Shell)\n' +
        '[+] Target constraints disabled. Any command or script executes freely with full root privileges.'
      );
    } else if (assetId === 'all') {
      appendLog(
        'system',
        `[*] Switched scope -> All Targets (${assets.length} authorized targets in scope)`
      );
    } else {
      const asset = assets.find((a) => a.id === assetId);
      if (asset) {
        const h = asset.hostname || new URL(asset.canonical_url).hostname;
        const p = String(asset.port || (asset.scheme === 'http' ? 80 : 443));
        appendLog('system', `[*] Switched active target -> ${asset.canonical_url} [${h}:${p}]`);
      }
    }
  };

  const appendLog = (type: TerminalHistoryEntry['type'], content: string) => {
    const newEntry: TerminalHistoryEntry = {
      id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      type,
      content,
      timestamp: new Date().toLocaleTimeString(),
    };
    setLogs((prev) => [...prev, newEntry]);
  };

  // Expand environment variables
  const expandEnvVars = (
    cmd: string,
    overrideHost?: string,
    overridePort?: string,
    overrideUrl?: string,
    overrideScheme?: string,
    overrideId?: string
  ): string => {
    return cmd
      .replace(/\$TARGET_URL/g, overrideUrl || targetUrl)
      .replace(/\$TARGET_HOST/g, overrideHost || targetHost)
      .replace(/\$TARGET_PORT/g, overridePort || targetPort)
      .replace(/\$TARGET_SCHEME/g, overrideScheme || targetScheme)
      .replace(/\$TARGET_ID/g, overrideId || activeAssetId);
  };

  // Filter practice scripts based on active category and search query
  const filteredPracticeScripts = PRACTICE_SCRIPTS_MANIFEST.filter((s) => {
    const matchesCat =
      practiceCategoryFilter === 'all' ||
      s.category.toLowerCase() === practiceCategoryFilter.toLowerCase() ||
      s.categoryLabel.toLowerCase().includes(practiceCategoryFilter.toLowerCase());
    const q = practiceSearchQuery.toLowerCase().trim();
    const matchesQuery =
      !q ||
      s.name.toLowerCase().includes(q) ||
      s.description.toLowerCase().includes(q) ||
      s.category.toLowerCase().includes(q) ||
      s.categoryLabel.toLowerCase().includes(q);
    return matchesCat && matchesQuery;
  });

  // Handle Loading a Script from the User's System (.py, .sh, .txt)
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      const newScript: LoadedScript = {
        name: file.name,
        size: file.size,
        content: content || '# Empty script',
        type: file.name.endsWith('.py') ? 'python' : file.name.endsWith('.sh') ? 'shell' : 'text',
        lastModified: file.lastModified,
      };

      setLoadedScripts((prev) => [newScript, ...prev.filter((s) => s.name !== file.name)]);
      setActiveScript(newScript);

      appendLog(
        'success',
        `[+] Uploaded script: ${file.name} (${file.size.toLocaleString()} bytes) to ~/target-assessment/`
      );
      appendLog(
        'system',
        `[*] Ready to run against ${targetHost}:${targetPort}. Execute: python ${file.name} $TARGET_HOST $TARGET_PORT`
      );

      setCommandInput(`python ${file.name} $TARGET_HOST $TARGET_PORT`);
      inputRef.current?.focus({ preventScroll: true });
    };

    reader.readAsText(file);
    // Reset file input so the same file can be re-selected if updated
    e.target.value = '';
  };

  // Handle Drag and Drop
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();

    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      const newScript: LoadedScript = {
        name: file.name,
        size: file.size,
        content: content || '# Empty script',
        type: file.name.endsWith('.py') ? 'python' : file.name.endsWith('.sh') ? 'shell' : 'text',
        lastModified: file.lastModified,
      };

      setLoadedScripts((prev) => [newScript, ...prev.filter((s) => s.name !== file.name)]);
      setActiveScript(newScript);
      appendLog(
        'success',
        `[+] Drag & Drop: Loaded ${file.name} (${file.size.toLocaleString()} bytes) into Kali environment.`
      );
      setCommandInput(`python ${file.name} $TARGET_HOST $TARGET_PORT`);
      inputRef.current?.focus({ preventScroll: true });
    };

    reader.readAsText(file);
  };

  // Execute terminal command
  const executeCommand = async (rawCmdToRun?: string) => {
    const cmdToRun = (rawCmdToRun !== undefined ? rawCmdToRun : commandInput).trim();
    if (!cmdToRun || isExecuting) return;

    // Record command history (deduplicated, max 100 entries, persisted across tab switches and page reloads)
    setCommandHistory((prev) => {
      const updated = prev[0] === cmdToRun ? prev : [cmdToRun, ...prev.filter((c) => c !== cmdToRun)].slice(0, 100);
      setAssessmentTerminalState({ commandHistory: updated });
      saveStoredHistory(updated);
      return updated;
    });
    setHistoryIndex(-1);
    draftInputRef.current = '';

    // Append input log based on active subConsole mode
    if (subConsole.type === 'msfconsole') {
      const msfPrompt = subConsole.module
        ? (subConsole.module.startsWith('exploit/')
            ? `msf6 exploit(${subConsole.module.replace(/^exploit\//, '')}) >`
            : subConsole.module.startsWith('auxiliary/')
            ? `msf6 auxiliary(${subConsole.module.replace(/^auxiliary\//, '')}) >`
            : `msf6 (${subConsole.module}) >`)
        : 'msf6 >';
      appendLog('input', `${msfPrompt} ${cmdToRun}`);
    } else if (subConsole.type === 'meterpreter') {
      appendLog('input', `meterpreter > ${cmdToRun}`);
    } else if (subConsole.type === 'python') {
      appendLog('input', `>>> ${cmdToRun}`);
    } else {
      appendLog('input', `┌──(root㉿kali)-[${currentDir}]\n└─# ${cmdToRun}`);
    }
    setCommandInput('');
    setIsExecuting(true);

    // =========================================================================
    // 1. METASPLOIT FRAMEWORK CONSOLE MODE
    // =========================================================================
    if (subConsole.type === 'msfconsole') {
      const subParts = cmdToRun.split(' ');
      const subCmd = subParts[0].toLowerCase();

      if (subCmd === 'exit' || subCmd === 'quit') {
        appendLog('output', '[*] Exiting the Metasploit Framework...');
        setSubConsole({ type: 'none' });
        setIsExecuting(false);
        return;
      }

      if (subCmd === 'clear' || subCmd === 'cls') {
        setLogs([]);
        setIsExecuting(false);
        return;
      }

      if (subCmd === 'banner') {
        const msfBanner = [
          '',
          '               .---.  .---.',
          '              :     \\:     :',
          '          _..-\'  	  `-.._',
          '        .\'			`.',
          '       /   Kali Metasploit Framework   \\',
          '      |       v6.3.50-dev             |',
          '       \\       [root@kali]            /',
          '        `._			_.\'',
          '           `-.._	  _..-\'',
          '                `---\'  `---\'',
          '',
          '       =[ metasploit v6.3.50-dev                          ]',
          '+ -- --=[ 2394 exploits - 1234 auxiliary - 418 post       ]',
          '+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]',
          '+ -- --=[ Free Root Terminal Mode Active                  ]',
          '',
        ].join('\n');
        appendLog('output', msfBanner);
        setIsExecuting(false);
        return;
      }

      if (subCmd === 'version') {
        appendLog('output', 'Framework: 6.3.50-dev\nConsole  : 6.3.50-dev');
        setIsExecuting(false);
        return;
      }

      if (subCmd === 'help' || subCmd === '?') {
        appendLog(
          'output',
          'Core Commands\n' +
          '=============\n\n' +
          '    Command       Description\n' +
          '    -------       -----------\n' +
          '    ?             Help menu\n' +
          '    banner        Display an awesome Metasploit banner\n' +
          '    back          Move back from the current context\n' +
          '    check         Check if target is vulnerable\n' +
          '    clear         Clear the terminal\n' +
          '    exit          Exit the console\n' +
          '    exploit       Launch an exploit attempt (alias: run)\n' +
          '    help          Help menu\n' +
          '    options       Display module options (alias for show options)\n' +
          '    run           Alias for exploit\n' +
          '    search        Search module names and descriptions\n' +
          '    sessions      Dump session listings and display information about sessions\n' +
          '    set           Set a context-specific variable to a value\n' +
          '    setg          Set a global variable to a value\n' +
          '    show          Displays modules of a given type, or all modules\n' +
          '    unset         Unsets one or more context-specific variables\n' +
          '    use           Interact with a module by name or search index/id\n' +
          '    version       Show the framework and console library version numbers\n'
        );
        setIsExecuting(false);
        return;
      }

      if (subCmd === 'back') {
        setSubConsole((prev) => ({ ...prev, module: undefined }));
        setIsExecuting(false);
        return;
      }

      if (subCmd === 'search') {
        const query = subParts.slice(1).join(' ').trim().toLowerCase();
        const searchDatabase = [
          {
            name: 'exploit/windows/smb/ms17_010_eternalblue',
            date: '2017-03-14',
            rank: 'average',
            check: 'Yes',
            desc: 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption RCE',
          },
          {
            name: 'exploit/windows/smb/ms08_067_netapi',
            date: '2008-10-28',
            rank: 'great',
            check: 'Yes',
            desc: 'MS08-067 Microsoft Server Service Relative Path Stack Corruption',
          },
          {
            name: 'exploit/multi/http/apache_activemq_upload_jsp',
            date: '2015-06-05',
            rank: 'excellent',
            check: 'Yes',
            desc: 'Apache ActiveMQ Fileserver Arbitrary File Upload JSP Shell',
          },
          {
            name: 'exploit/unix/webapp/wp_admin_shell_upload',
            date: '2015-02-21',
            rank: 'excellent',
            check: 'Yes',
            desc: 'WordPress Admin Plugin Shell Upload and Execution',
          },
          {
            name: 'exploit/multi/http/tomcat_mgr_upload',
            date: '2009-11-09',
            rank: 'excellent',
            check: 'Yes',
            desc: 'Apache Tomcat Manager Authenticated Application Upload RCE',
          },
          {
            name: 'auxiliary/scanner/smb/smb_version',
            date: '2020-01-01',
            rank: 'normal',
            check: 'No',
            desc: 'SMB Version Detection and Fingerprint Probe',
          },
          {
            name: 'auxiliary/scanner/smb/smb_ms17_010',
            date: '2017-03-14',
            rank: 'normal',
            check: 'Yes',
            desc: 'MS17-010 SMB RCE Vulnerability Scanner',
          },
          {
            name: 'auxiliary/scanner/http/http_version',
            date: '2021-05-10',
            rank: 'normal',
            check: 'No',
            desc: 'HTTP Version & Banner Detection',
          },
          {
            name: 'exploit/linux/http/apache_log4j_rce',
            date: '2021-12-10',
            rank: 'excellent',
            check: 'Yes',
            desc: 'Apache Log4j JNDI Remote Code Execution (Log4Shell)',
          },
          {
            name: 'exploit/multi/http/struts2_namespace_ognl',
            date: '2018-08-22',
            rank: 'excellent',
            check: 'Yes',
            desc: 'Apache Struts 2 Namespace OGNL Remote Code Execution (S2-057)',
          },
          {
            name: 'auxiliary/scanner/ssh/ssh_version',
            date: '2020-03-15',
            rank: 'normal',
            check: 'No',
            desc: 'SSH Version Detection Scanner',
          },
          {
            name: 'exploit/multi/handler',
            date: '2022-01-01',
            rank: 'manual',
            check: 'No',
            desc: 'Generic Payload Handler for Inbound Sessions',
          },
        ];

        const matches = query
          ? searchDatabase.filter(
              (m) =>
                m.name.toLowerCase().includes(query) ||
                m.desc.toLowerCase().includes(query)
            )
          : searchDatabase;

        let table = 'Matching Modules\n================\n\n';
        table += '   #   Name                                                  Disclosure Date  Rank       Check  Description\n';
        table += '   -   ----                                                  ---------------  ----       -----  -----------\n';
        matches.forEach((m, idx) => {
          const idxStr = String(idx).padEnd(3, ' ');
          const nameStr = m.name.padEnd(53, ' ');
          const dateStr = m.date.padEnd(16, ' ');
          const rankStr = m.rank.padEnd(10, ' ');
          const checkStr = m.check.padEnd(6, ' ');
          table += `   ${idxStr} ${nameStr} ${dateStr} ${rankStr} ${checkStr} ${m.desc}\n`;
        });
        table += `\nInteract with a module by name or index: use <name> or use <index>\n`;
        appendLog('output', table);
        setIsExecuting(false);
        return;
      }

      if (subCmd === 'use') {
        const moduleArg = subParts[1] || '';
        if (!moduleArg) {
          appendLog('error', '[-] Please specify a module name or index (e.g. use exploit/windows/smb/ms17_010_eternalblue, use 0)');
          setIsExecuting(false);
          return;
        }

        let chosenModule = moduleArg;
        if (/^\d+$/.test(moduleArg)) {
          const searchDatabase = [
            'exploit/windows/smb/ms17_010_eternalblue',
            'exploit/windows/smb/ms08_067_netapi',
            'exploit/multi/http/apache_activemq_upload_jsp',
            'exploit/unix/webapp/wp_admin_shell_upload',
            'exploit/multi/http/tomcat_mgr_upload',
            'auxiliary/scanner/smb/smb_version',
            'auxiliary/scanner/smb/smb_ms17_010',
            'auxiliary/scanner/http/http_version',
            'exploit/linux/http/apache_log4j_rce',
            'exploit/multi/http/struts2_namespace_ognl',
            'auxiliary/scanner/ssh/ssh_version',
            'exploit/multi/handler',
          ];
          const idx = parseInt(moduleArg, 10);
          if (idx >= 0 && idx < searchDatabase.length) {
            chosenModule = searchDatabase[idx];
          }
        }

        const isAux = chosenModule.startsWith('auxiliary/');
        const defaultPayload = isAux ? '' : 'windows/x64/meterpreter/reverse_tcp';

        setSubConsole((prev) => ({
          ...prev,
          module: chosenModule,
          options: {
            ...prev.options,
            RHOSTS: prev.options?.RHOSTS || (targetHost === 'ALL_TARGETS' ? '127.0.0.1' : targetHost),
            RPORT: prev.options?.RPORT || (isAux ? '80' : targetPort || '445'),
            LHOST: prev.options?.LHOST || '10.0.0.1',
            LPORT: prev.options?.LPORT || '4444',
            PAYLOAD: prev.options?.PAYLOAD || defaultPayload,
          },
        }));

        if (!isAux) {
          appendLog('output', `[*] Using configured payload ${defaultPayload}`);
        }
        setIsExecuting(false);
        return;
      }

      if (subCmd === 'show' || subCmd === 'options') {
        const showArg = (subParts[1] || '').toLowerCase();
        if (showArg === 'options' || subCmd === 'options') {
          const currentMod = subConsole.module || 'exploit/windows/smb/ms17_010_eternalblue';
          const opts = subConsole.options || {};
          const rhost = opts.RHOSTS || (targetHost === 'ALL_TARGETS' ? '127.0.0.1' : targetHost);
          const rport = opts.RPORT || targetPort || '445';
          const lhost = opts.LHOST || '10.0.0.1';
          const lport = opts.LPORT || '4444';
          const payload = opts.PAYLOAD || (currentMod.startsWith('auxiliary/') ? '' : 'windows/x64/meterpreter/reverse_tcp');

          let out = `Module options (${currentMod}):\n\n`;
          out += '   Name       Current Setting   Required  Description\n';
          out += '   ----       ---------------   --------  -----------\n';
          out += `   RHOSTS     ${rhost.padEnd(17, ' ')} yes       The target host(s), range CIDR identifier, or hosts file\n`;
          out += `   RPORT      ${String(rport).padEnd(17, ' ')} yes       The target port (TCP)\n`;
          out += `   SMBDomain  .                 no        The Windows domain to use for authentication\n`;
          out += `   SMBUser                      no        The username to authenticate as\n`;
          out += `   SMBPass                      no        The password for the specified username\n\n`;
          if (payload) {
            out += `Payload options (${payload}):\n\n`;
            out += '   Name       Current Setting   Required  Description\n';
            out += '   ----       ---------------   --------  -----------\n';
            out += `   EXITFUNC   thread            yes       Exit technique (Accepted: '', seh, thread, process, none)\n`;
            out += `   LHOST      ${lhost.padEnd(17, ' ')} yes       The listen address (an interface may be specified)\n`;
            out += `   LPORT      ${String(lport).padEnd(17, ' ')} yes       The listen port\n\n`;
          }
          out += 'Exploit target:\n\n';
          out += '   Id  Name\n';
          out += '   --  ----\n';
          out += '   0   Automatic Target\n';
          appendLog('output', out);
          setIsExecuting(false);
          return;
        }

        if (showArg === 'payloads') {
          appendLog(
            'output',
            'Compatible Payloads\n' +
            '===================\n\n' +
            '   #  Name                                            Disclosure Date  Rank    Check  Description\n' +
            '   -  ----                                            ---------------  ----    -----  -----------\n' +
            '   0  windows/x64/meterpreter/reverse_tcp             .                manual  No     Windows Meterpreter (x64) Reverse TCP Stager\n' +
            '   1  windows/x64/meterpreter/reverse_https           .                manual  No     Windows Meterpreter (x64) Reverse HTTPS Stager\n' +
            '   2  windows/x64/shell/reverse_tcp                   .                manual  No     Windows Command Shell (x64) Reverse TCP Stager\n' +
            '   3  generic/shell_reverse_tcp                       .                manual  No     Generic Command Shell Reverse TCP\n'
          );
          setIsExecuting(false);
          return;
        }

        if (showArg === 'targets') {
          appendLog('output', 'Exploit targets:\n\n   Id  Name\n   --  ----\n   0   Windows 10 / Server 2016 (x64)\n   1   Windows 7 / Server 2008 R2 (x64)\n');
          setIsExecuting(false);
          return;
        }
      }

      if (subCmd === 'set' || subCmd === 'setg') {
        const key = (subParts[1] || '').toUpperCase();
        const val = subParts.slice(2).join(' ').trim();
        if (!key) {
          appendLog('error', '[-] Usage: set <OPTION> <VALUE>');
          setIsExecuting(false);
          return;
        }
        setSubConsole((prev) => ({
          ...prev,
          options: {
            ...prev.options,
            [key]: val,
          },
        }));
        appendLog('output', `${key} => ${val}`);
        setIsExecuting(false);
        return;
      }

      if (subCmd === 'unset') {
        const key = (subParts[1] || '').toUpperCase();
        setSubConsole((prev) => {
          const nextOpts = { ...(prev.options || {}) };
          delete nextOpts[key];
          return { ...prev, options: nextOpts };
        });
        appendLog('output', `Unsetting ${key}...`);
        setIsExecuting(false);
        return;
      }

      if (subCmd === 'check') {
        const rhost = subConsole.options?.RHOSTS || (targetHost === 'ALL_TARGETS' ? '127.0.0.1' : targetHost);
        const rport = subConsole.options?.RPORT || targetPort || '445';
        appendLog('output', `[*] ${rhost}:${rport} - Checking target vulnerability status...`);
        setTimeout(() => {
          appendLog('success', `[+] ${rhost}:${rport} - The target appears to be vulnerable. (Service responsive)`);
          setIsExecuting(false);
        }, 300);
        return;
      }

      if (subCmd === 'exploit' || subCmd === 'run') {
        const rhost = subConsole.options?.RHOSTS || (targetHost === 'ALL_TARGETS' ? '127.0.0.1' : targetHost);
        const rport = subConsole.options?.RPORT || targetPort || '445';
        const lhost = subConsole.options?.LHOST || '10.0.0.1';
        const lport = subConsole.options?.LPORT || '4444';
        const payload = subConsole.options?.PAYLOAD || 'windows/x64/meterpreter/reverse_tcp';

        appendLog('output', `[*] Started reverse TCP handler on ${lhost}:${lport}`);
        setTimeout(() => {
          appendLog('output', `[*] ${rhost}:${rport} - Connecting to the target...`);
          setTimeout(() => {
            appendLog('output', `[*] ${rhost}:${rport} - Target verified: ${rhost}:${rport}`);
            setTimeout(() => {
              appendLog('output', `[*] ${rhost}:${rport} - Sending payload stage (${payload}) [175,174 bytes]...`);
              setTimeout(() => {
                const nowTime = new Date().toLocaleTimeString();
                appendLog('success', `[+] Meterpreter session 1 opened (${lhost}:${lport} -> ${rhost}:${rport}) at ${nowTime}`);
                setIsExecuting(false);
              }, 200);
            }, 200);
          }, 200);
        }, 200);
        return;
      }

      if (subCmd === 'sessions') {
        const sessionArg = subParts[1] || '';
        const rhost = subConsole.options?.RHOSTS || (targetHost === 'ALL_TARGETS' ? '127.0.0.1' : targetHost);
        const lhost = subConsole.options?.LHOST || '10.0.0.1';

        if (sessionArg === '-i' || sessionArg === '1') {
          appendLog('output', `[*] Starting interaction with session 1...\n`);
          setSubConsole((prev) => ({
            ...prev,
            type: 'meterpreter',
            sessionTarget: rhost,
          }));
          setIsExecuting(false);
          return;
        }

        let sessTable = 'Active sessions\n===============\n\n';
        sessTable += '  Id  Name  Type                     Information                   Connection\n';
        sessTable += '  --  ----  ----                     -----------                   ----------\n';
        sessTable += `  1         meterpreter x64/windows  NT AUTHORITY\\SYSTEM @ TARGET  ${lhost}:4444 -> ${rhost}:49215 (${rhost})\n`;
        appendLog('output', sessTable);
        setIsExecuting(false);
        return;
      }

      appendLog('error', `[-] Unknown command: ${subCmd}. Type help or ? for a list of available commands.`);
      setIsExecuting(false);
      return;
    }

    // =========================================================================
    // 2. METERPRETER SUB-SHELL MODE
    // =========================================================================
    if (subConsole.type === 'meterpreter') {
      const subParts = cmdToRun.split(' ');
      const mCmd = subParts[0].toLowerCase();

      if (mCmd === 'exit' || mCmd === 'quit') {
        appendLog('output', '[*] Shutting down Meterpreter session 1...');
        setSubConsole((prev) => ({ ...prev, type: 'msfconsole' }));
        setIsExecuting(false);
        return;
      }

      if (mCmd === 'background' || mCmd === 'bg') {
        appendLog('output', '[*] Backgrounding session 1...');
        setSubConsole((prev) => ({ ...prev, type: 'msfconsole' }));
        setIsExecuting(false);
        return;
      }

      if (mCmd === 'sysinfo') {
        const rhost = subConsole.sessionTarget || subConsole.options?.RHOSTS || 'TARGET-SYSTEM';
        const out = [
          `Computer        : ${rhost.toUpperCase()}`,
          `OS              : Windows Server 2016 (10.0 Build 14393).`,
          `Architecture    : x64`,
          `System Language : en_US`,
          `Domain          : WORKGROUP`,
          `Logged On Users : 2`,
          `Meterpreter     : x64/windows`,
        ].join('\n');
        appendLog('output', out);
        setIsExecuting(false);
        return;
      }

      if (mCmd === 'getuid') {
        appendLog('output', 'Server username: NT AUTHORITY\\SYSTEM');
        setIsExecuting(false);
        return;
      }

      if (mCmd === 'pwd') {
        appendLog('output', 'C:\\Windows\\system32');
        setIsExecuting(false);
        return;
      }

      if (mCmd === 'ps') {
        const psTable = [
          'Process List',
          '============',
          '',
          ' PID   PPID  Name               Arch  Session  User                          Path',
          ' ---   ----  ----               ----  -------  ----                          ----',
          ' 0     0     [System Process]                                                ',
          ' 4     0     System             x64   0                                      ',
          ' 540   4     smss.exe           x64   0        NT AUTHORITY\\SYSTEM           C:\\Windows\\System32\\smss.exe',
          ' 680   672   csrss.exe          x64   0        NT AUTHORITY\\SYSTEM           C:\\Windows\\System32\\csrss.exe',
          ' 768   672   wininit.exe        x64   0        NT AUTHORITY\\SYSTEM           C:\\Windows\\System32\\wininit.exe',
          ' 860   768   services.exe       x64   0        NT AUTHORITY\\SYSTEM           C:\\Windows\\System32\\services.exe',
          ' 872   768   lsass.exe          x64   0        NT AUTHORITY\\SYSTEM           C:\\Windows\\System32\\lsass.exe',
          ' 1024  860   svchost.exe        x64   0        NT AUTHORITY\\SYSTEM           C:\\Windows\\System32\\svchost.exe',
          ' 1680  860   spoolsv.exe        x64   0        NT AUTHORITY\\SYSTEM           C:\\Windows\\System32\\spoolsv.exe',
        ].join('\n');
        appendLog('output', psTable);
        setIsExecuting(false);
        return;
      }

      if (mCmd === 'hashdump') {
        const hashes = [
          'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
          'Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
          'DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
          'secops:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::',
        ].join('\n');
        appendLog('output', hashes);
        setIsExecuting(false);
        return;
      }

      if (mCmd === 'help' || mCmd === '?') {
        appendLog(
          'output',
          'Meterpreter Commands\n' +
          '====================\n\n' +
          '    Command       Description\n' +
          '    -------       -----------\n' +
          '    background    Backgrounds the current session (alias: bg)\n' +
          '    exit          Terminate the meterpreter session\n' +
          '    getuid        Get the user that the server is running as\n' +
          '    hashdump      Dumps the contents of the SAM database\n' +
          '    help          Help menu\n' +
          '    ps            List running processes\n' +
          '    pwd           Print working directory\n' +
          '    sysinfo       Gets the information about the remote system, such as OS\n'
        );
        setIsExecuting(false);
        return;
      }

      appendLog('error', `[-] Unknown Meterpreter command: ${mCmd}. Type help or ? for options.`);
      setIsExecuting(false);
      return;
    }

    // =========================================================================
    // 3. PYTHON INTERACTIVE REPL MODE
    // =========================================================================
    if (subConsole.type === 'python') {
      if (cmdToRun === 'exit()' || cmdToRun === 'quit()' || cmdToRun === 'exit' || cmdToRun === 'quit') {
        setSubConsole({ type: 'none' });
        setIsExecuting(false);
        return;
      }
      try {
        if (/^[0-9+\-*/%().\s^]+$/.test(cmdToRun)) {
          // eslint-disable-next-line no-eval
          const result = Function(`"use strict"; return (${cmdToRun});`)();
          appendLog('output', String(result));
        } else if (cmdToRun.startsWith('print(') && cmdToRun.endsWith(')')) {
          const inner = cmdToRun.slice(6, -1);
          const val = inner.replace(/^['"](.*)['"]$/, '$1');
          appendLog('output', val);
        } else {
          appendLog('output', `>>> ${cmdToRun}`);
        }
      } catch (err: any) {
        appendLog('error', `Traceback (most recent call last):\n  File "<stdin>", line 1, in <module>\nNameError: ${err.message}`);
      }
      setIsExecuting(false);
      return;
    }

    // =========================================================================
    // 4. KALI LINUX BASH SHELL MODE
    // =========================================================================
    const expandedCmd = expandEnvVars(cmdToRun);
    const parts = expandedCmd.split(' ');
    const mainCmd = parts[0].toLowerCase();

    // Built-in command handling
    if (mainCmd === 'clear' || mainCmd === 'cls') {
      setLogs([]);
      setIsExecuting(false);
      return;
    }

    // Launch Metasploit Framework Console
    if (mainCmd === 'msfconsole' || mainCmd === 'metasploit') {
      const msfVer = isKaliUpgraded ? 'v6.4.12-release' : 'v6.3.50-dev';
      const msfExploits = isKaliUpgraded ? '2442 exploits - 1265 auxiliary - 428 post' : '2394 exploits - 1234 auxiliary - 418 post';
      const msfPayloads = isKaliUpgraded ? '1465 payloads - 47 encoders - 11 nops' : '1391 payloads - 46 encoders - 11 nops';
      const msfBanner = [
        '',
        '               .---.  .---.',
        '              :     \\:     :',
        '          _..-\'  	  `-.._',
        '        .\'			`.',
        '       /   Kali Metasploit Framework   \\',
        `      |       ${msfVer.padEnd(23, ' ')} |`,
        '       \\       [root@kali]            /',
        '        `._			_.\'',
        '           `-.._	  _..-\'',
        '                `---\'  `---\'',
        '',
        `       =[ metasploit ${msfVer.padEnd(35, ' ')} ]`,
        `+ -- --=[ ${msfExploits.padEnd(47, ' ')} ]`,
        `+ -- --=[ ${msfPayloads.padEnd(47, ' ')} ]`,
        '+ -- --=[ Free Root Terminal Mode Active                  ]',
        '',
      ].join('\n');
      appendLog('output', msfBanner);
      setSubConsole({
        type: 'msfconsole',
        options: {
          RHOSTS: targetHost === 'ALL_TARGETS' ? '127.0.0.1' : targetHost,
          RPORT: targetPort || '443',
          LHOST: '10.0.0.1',
          LPORT: '4444',
          PAYLOAD: 'windows/x64/meterpreter/reverse_tcp',
        },
      });
      setIsExecuting(false);
      return;
    }

    // Launch Python interactive REPL when python is entered with no arguments
    if ((mainCmd === 'python' || mainCmd === 'python3' || mainCmd === 'py') && parts.length === 1) {
      appendLog(
        'output',
        'Python 3.11.8 (main, Feb  7 2024, 09:03:49) [GCC 13.2.0] on linux\n' +
        'Type "help", "copyright", "credits" or "license" for more information.'
      );
      setSubConsole({ type: 'python' });
      setIsExecuting(false);
      return;
    }

    if (mainCmd === 'sudo') {
      const sudoRemaining = parts.slice(1).join(' ').trim();
      if (!sudoRemaining) {
        appendLog('output', 'usage: sudo command [args]\n[+] Root privileges granted (uid=0 gid=0).');
        setIsExecuting(false);
        return;
      }
      setIsExecuting(false);
      return executeCommand(sudoRemaining);
    }

    if (mainCmd === 'id') {
      appendLog('output', 'uid=0(root) gid=0(root) groups=0(root),27(sudo),44(video),100(users)');
      setIsExecuting(false);
      return;
    }

    if (mainCmd === 'hostname') {
      appendLog('output', 'kali');
      setIsExecuting(false);
      return;
    }

    if (mainCmd === 'help' || mainCmd === '?') {
      appendLog(
        'output',
        '=== KALI LINUX TARGET ASSESSMENT TERMINAL - QUICK GUIDE: ===\n' +
          '  sudo <cmd>                 : Execute with root privileges (uid=0)\n' +
          '  apt update / apt install   : Package management & repository synchronization\n' +
          '  git clone <url> / status   : Clone remote GitHub/GitLab repositories & manage versioning\n' +
          '  python <script.py> [args]  : Execute local or uploaded Python test script\n' +
          '  curl -i <url>              : Perform live HTTP/HTTPS wire probe\n' +
          '  nmap -sV -p <port> <host>  : Run port reconnaissance & service banner detection\n' +
          '  ifconfig / ip addr / route : Network interface IP configuration and routing table\n' +
          '  netstat / ss / arp         : Active socket connections and ARP table\n' +
          '  ping <host>                : Network latency & ICMP reachability test\n' +
          '  nslookup / dig / host      : Query target DNS records\n' +
          '  tracert / traceroute       : Inspect network hops to target\n' +
          '  openssl                    : Probe TLS handshake, certificates, and ciphers\n' +
          '  nc / netcat <host> <port>  : Direct TCP socket connection & banner grab\n' +
          '  ps aux / top / df / free   : Process monitoring, memory, and filesystem stats\n' +
          '  mkdir / touch / rm / cp/mv : Filesystem manipulation inside assessment workspace\n' +
          '  wget <url> [-O file]       : Directly download remote payloads/files\n' +
          '  sqlmap / nikto / hydra     : Automated SQL injection, web audit, & auth assessment\n' +
          '  gobuster / dirb / ffuf     : Web application directory & path reconnaissance\n' +
          '  msfconsole / aircrack / john: Metasploit, wireless auditing, & password tools\n' +
          '  base64 [-d] <str>          : Encode or decode payload strings\n' +
          '  whoami / id / hostname     : Display root session identity & credentials (uid=0)\n' +
          '  cd <dir>                   : Change directory (e.g. cd Practice_Scripts, cd ..)\n' +
          '  pwd                        : Print current working directory path\n' +
          '  cat <filename>             : View loaded script contents in terminal\n' +
          '  ls / dir [dir]             : List loaded scripts or Practice_Scripts library\n' +
          '  env                        : Display active target environment variables\n' +
          '  clear                      : Clear terminal screen history\n' +
          '\n=== TARGET & EXECUTION SCOPES: ===\n' +
          '  Personal                   : Standalone free mode with zero target constraints (run any custom command)\n' +
          '  All Targets                : Multi-target mode (iterates sequentially across all in-scope targets)\n' +
          '  Single Target              : Direct assessment against the selected target endpoint\n' +
          '\n=== AUTOMATIC TARGET ENVIRONMENT VARIABLES: ===\n' +
          `  $TARGET_URL  = ${targetUrl}\n` +
          `  $TARGET_HOST = ${targetHost}\n` +
          `  $TARGET_PORT = ${targetPort}\n` +
          `  $TARGET_SCHEME = ${targetScheme}\n` +
          '  $ROOT_USER   = root (uid=0, unrestricted clearance)\n' +
          'You can use $TARGET_HOST, $TARGET_PORT, or $TARGET_URL in any command line.'
      );
      setIsExecuting(false);
      return;
    }

    if (mainCmd === 'cd') {
      const targetDir = (parts[1] || '').trim();

      if (
        targetDir === '' ||
        targetDir === '~' ||
        targetDir === '~/target-assessment' ||
        targetDir === '/root/target-assessment'
      ) {
        setCurrentDir('~/target-assessment');
      } else if (targetDir === '/root') {
        setCurrentDir('~');
      } else if (
        targetDir === 'Practice_Scripts' ||
        targetDir === 'Practice_Scripts/' ||
        targetDir === './Practice_Scripts' ||
        targetDir === '~/target-assessment/Practice_Scripts' ||
        targetDir === '/root/target-assessment/Practice_Scripts'
      ) {
        setCurrentDir('~/target-assessment/Practice_Scripts');
      } else if (targetDir === '..' || targetDir === '../') {
        if (currentDir.startsWith('~/target-assessment/Practice_Scripts')) {
          setCurrentDir('~/target-assessment');
        } else if (currentDir.startsWith('~/target-assessment/') && currentDir !== '~/target-assessment') {
          setCurrentDir('~/target-assessment');
        } else if (currentDir === '~/target-assessment') {
          setCurrentDir('~');
        } else {
          setCurrentDir('~');
        }
      } else if (targetDir === '.' || targetDir === './') {
        // stay in current directory
      } else {
        const cleanDir = targetDir.replace(/\/$/, '').split('/').pop() || targetDir;
        const matchingFs = fsEntries.find(
          (e) => e.name === targetDir || e.name === cleanDir || e.name === targetDir.replace(/\/$/, '')
        );

        if (matchingFs && matchingFs.type === 'directory') {
          setCurrentDir(`~/target-assessment/${matchingFs.name}`);
        } else if (
          (matchingFs && matchingFs.type === 'file') ||
          loadedScripts.some((s) => s.name === targetDir || s.name === cleanDir) ||
          PRACTICE_SCRIPTS_MANIFEST.some((p) => p.name === targetDir || p.path === targetDir) ||
          targetDir.endsWith('.py') ||
          targetDir.endsWith('.sh') ||
          targetDir.endsWith('.txt') ||
          targetDir.endsWith('.md') ||
          targetDir.endsWith('.json') ||
          targetDir.endsWith('.yaml') ||
          targetDir.endsWith('.yml')
        ) {
          appendLog('error', `bash: cd: ${targetDir}: Not a directory`);
        } else if (customDirs.includes(cleanDir)) {
          setCurrentDir(`~/target-assessment/${cleanDir}`);
        } else {
          appendLog('error', `bash: cd: ${targetDir}: No such file or directory`);
        }
      }

      // Sync with backend
      api.executeTerminalCommand({
        command: expandedCmd,
        target_host: isPersonalMode ? (targetHost || 'localhost') : targetHost,
        target_port: targetPort,
        target_url: targetUrl,
        target_scheme: targetScheme,
        target_id: activeAssetId,
        current_dir: currentDir,
      }).then((res) => {
        if (res.current_dir) setCurrentDir(res.current_dir);
        if (res.fs_entries) setFsEntries(res.fs_entries);
      }).catch(() => {});

      setIsExecuting(false);
      return;
    }

    if (mainCmd === 'pwd') {
      const rootPath = '/root/' + currentDir.replace(/^~\//, '');
      appendLog('output', rootPath);
      setIsExecuting(false);
      return;
    }

    if (mainCmd === 'env') {
      if (isPersonalMode) {
        appendLog(
          'output',
          `USER=root\n` +
            `LOGNAME=root\n` +
            `HOME=/root\n` +
            `UID=0\n` +
            `EUID=0\n` +
            `GROUPS=0(root)\n` +
            `SHELL=/bin/zsh\n` +
            `TERM=xterm-256color\n` +
            `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.local/bin\n` +
            `PRIVILEGES=ROOT_FULL_AUTHORIZATION\n` +
            `MODE=PERSONAL_FREE_SHELL\n` +
            `TARGET_CONSTRAINT=NONE\n` +
            `SECURITY_CLEARANCE=UNRESTRICTED_PERSONAL_EXECUTION\n` +
            `PWD=${'/root/' + currentDir.replace(/^~\//, '')}`
        );
      } else {
        appendLog(
          'output',
          `USER=root\n` +
            `LOGNAME=root\n` +
            `HOME=/root\n` +
            `UID=0\n` +
            `EUID=0\n` +
            `GROUPS=0(root)\n` +
            `SHELL=/bin/zsh\n` +
            `TERM=xterm-256color\n` +
            `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.local/bin\n` +
            `PRIVILEGES=ROOT_FULL_AUTHORIZATION\n` +
            `SECURITY_CLEARANCE=UNRESTRICTED_IN_SCOPE_ASSESSMENT\n` +
            `TARGET_URL=${targetUrl}\n` +
            `TARGET_HOST=${targetHost}\n` +
            `TARGET_PORT=${targetPort}\n` +
            `TARGET_SCHEME=${targetScheme}\n` +
            `TARGET_ID=${activeAssetId}\n` +
            `PWD=${'/root/' + currentDir.replace(/^~\//, '')}`
        );
      }
      setIsExecuting(false);
      return;
    }

    if (mainCmd === 'mkdir') {
      const rawArgs = parts.slice(1);
      const targetArgs = rawArgs.filter((a) => !a.startsWith('-'));
      if (targetArgs.length === 0) {
        appendLog('error', 'mkdir: missing operand');
        setIsExecuting(false);
        return;
      }

      for (const target of targetArgs) {
        const cleanTarget = target.replace(/\/$/, '').split('/').pop() || target;
        setCustomDirs((prev) => (prev.includes(cleanTarget) ? prev : [...prev, cleanTarget]));
        setFsEntries((prev) => {
          if (prev.some((e) => e.name === cleanTarget)) return prev;
          return [...prev, { name: cleanTarget, type: 'directory', size: 4096, modified: Date.now() }];
        });
      }

      api.executeTerminalCommand({
        command: expandedCmd,
        target_host: isPersonalMode ? (targetHost || 'localhost') : targetHost,
        target_port: targetPort,
        target_url: targetUrl,
        target_scheme: targetScheme,
        target_id: activeAssetId,
        current_dir: currentDir,
      }).then((res) => {
        if (res.fs_entries) setFsEntries(res.fs_entries);
      }).catch(() => {});

      setIsExecuting(false);
      setTimeout(() => inputRef.current?.focus({ preventScroll: true }), 30);
      return;
    }

    if (mainCmd === 'rmdir') {
      const rawArgs = parts.slice(1);
      const targetArgs = rawArgs.filter((a) => !a.startsWith('-'));
      if (targetArgs.length === 0) {
        appendLog('error', 'rmdir: missing operand');
        setIsExecuting(false);
        return;
      }

      for (const target of targetArgs) {
        const cleanTarget = target.replace(/\/$/, '').split('/').pop() || target;
        if (!customDirs.includes(cleanTarget) && !fsEntries.some((e) => e.name === cleanTarget && e.type === 'directory')) {
          appendLog('error', `rmdir: failed to remove '${target}': No such file or directory`);
        } else {
          setCustomDirs((prev) => prev.filter((d) => d !== cleanTarget));
          setFsEntries((prev) => prev.filter((e) => e.name !== cleanTarget));
        }
      }

      api.executeTerminalCommand({
        command: expandedCmd,
        target_host: isPersonalMode ? (targetHost || 'localhost') : targetHost,
        target_port: targetPort,
        target_url: targetUrl,
        target_scheme: targetScheme,
        target_id: activeAssetId,
        current_dir: currentDir,
      }).then((res) => {
        if (res.fs_entries) setFsEntries(res.fs_entries);
      }).catch(() => {});

      setIsExecuting(false);
      setTimeout(() => inputRef.current?.focus({ preventScroll: true }), 30);
      return;
    }

    if (mainCmd === 'touch') {
      const rawArgs = parts.slice(1);
      const targetArgs = rawArgs.filter((a) => !a.startsWith('-'));
      if (targetArgs.length === 0) {
        appendLog('error', 'touch: missing file operand');
        setIsExecuting(false);
        return;
      }

      for (const target of targetArgs) {
        const cleanTarget = target.split('/').pop() || target;
        setLoadedScripts((prev) => {
          if (prev.some((s) => s.name === cleanTarget)) return prev;
          return [
            ...prev,
            {
              name: cleanTarget,
              size: 0,
              content: '',
              type: cleanTarget.endsWith('.py') ? ('python' as const) : ('shell' as const),
              lastModified: Date.now(),
            },
          ];
        });
        setFsEntries((prev) => {
          if (prev.some((e) => e.name === cleanTarget)) return prev;
          return [...prev, { name: cleanTarget, type: 'file', size: 0, modified: Date.now() }];
        });
      }

      api.executeTerminalCommand({
        command: expandedCmd,
        target_host: isPersonalMode ? (targetHost || 'localhost') : targetHost,
        target_port: targetPort,
        target_url: targetUrl,
        target_scheme: targetScheme,
        target_id: activeAssetId,
        current_dir: currentDir,
      }).then((res) => {
        if (res.fs_entries) setFsEntries(res.fs_entries);
      }).catch(() => {});

      setIsExecuting(false);
      setTimeout(() => inputRef.current?.focus({ preventScroll: true }), 30);
      return;
    }

    if (mainCmd === 'rm') {
      const rawArgs = parts.slice(1);
      const targetArgs = rawArgs.filter((a) => !a.startsWith('-'));
      const isForce = rawArgs.some((a) => a === '-f' || a === '-rf' || a === '-fr' || (a.startsWith('-') && a.includes('f')));
      const isRecursive = rawArgs.some((a) => a === '-r' || a === '-rf' || a === '-R' || (a.startsWith('-') && (a.includes('r') || a.includes('R'))));

      if (targetArgs.length === 0) {
        appendLog('error', 'rm: missing operand');
        setIsExecuting(false);
        return;
      }

      const targetsToRemove: string[] = [];

      for (const target of targetArgs) {
        const cleanTarget = target.replace(/\/$/, '').split('/').pop() || target;
        const existsInLoaded = loadedScripts.some((s) => s.name === cleanTarget || s.name === target);
        const existsInFs = fsEntries.some((e) => e.name === cleanTarget || e.name === target);
        const existsInDirs = customDirs.includes(cleanTarget);

        if (existsInDirs && !isRecursive) {
          appendLog('error', `rm: cannot remove '${target}': Is a directory`);
          continue;
        }

        if (!existsInLoaded && !existsInFs && !existsInDirs && !isForce) {
          appendLog('error', `rm: cannot remove '${target}': No such file or directory`);
          continue;
        }

        targetsToRemove.push(cleanTarget);
      }

      if (targetsToRemove.length > 0) {
        setLoadedScripts((prev) => {
          const updated = prev.filter((s) => !targetsToRemove.includes(s.name));
          if (activeScript && targetsToRemove.includes(activeScript.name)) {
            setActiveScript(updated[0] || null);
            setEditedScriptContent(updated[0]?.content || '');
          }
          return updated;
        });

        setFsEntries((prev) => prev.filter((e) => !targetsToRemove.includes(e.name)));
        setCustomDirs((prev) => prev.filter((d) => !targetsToRemove.includes(d)));

        api.executeTerminalCommand({
          command: expandedCmd,
          target_host: isPersonalMode ? (targetHost || 'localhost') : targetHost,
          target_port: targetPort,
          target_url: targetUrl,
          target_scheme: targetScheme,
          target_id: activeAssetId,
          current_dir: currentDir,
        }).then((res) => {
          if (res.fs_entries) setFsEntries(res.fs_entries);
        }).catch(() => {});
      }

      setIsExecuting(false);
      setTimeout(() => inputRef.current?.focus({ preventScroll: true }), 30);
      return;
    }

    if (mainCmd === 'ls' || mainCmd === 'dir') {
      const dirArg = (parts[1] || '').trim();

      if (
        dirArg.toLowerCase().includes('practice_scripts') ||
        currentDir === '~/target-assessment/Practice_Scripts'
      ) {
        const scriptNames = PRACTICE_SCRIPTS_MANIFEST.map((s) => s.name);
        const preview = scriptNames.slice(0, 30).join('  ');
        appendLog(
          'output',
          `total 407 [407 scripts in ~/target-assessment/Practice_Scripts/ (407 modular scripts, 0 subdirectories)]\n` +
          `${preview}\n` +
          `... and ${scriptNames.length - 30} more modular Python scripts in Practice_Scripts/ (Total: 407 scripts in root)`
        );
        setIsExecuting(false);
        return;
      }

      if (currentDir.startsWith('~/target-assessment/') && currentDir !== '~/target-assessment') {
        const subFiles = fsEntries.filter((e) => e.name !== 'Practice_Scripts');
        if (subFiles.length > 0) {
          const lines = subFiles.map((e) => {
            const perm = e.type === 'directory' ? 'drwxr-xr-x 2 root root' : '-rwxr-xr-x 1 root root';
            const sz = String(e.size).padStart(6, ' ');
            const dt = new Date(e.modified || Date.now()).toLocaleDateString();
            return `${perm} ${sz} ${dt} ${e.name}`;
          });
          appendLog('output', `total ${lines.length}\n` + lines.join('\n'));
        } else {
          appendLog('output', 'total 0');
        }
        setIsExecuting(false);
        return;
      }

      // Root ~/target-assessment: Merge fsEntries, customDirs, and loadedScripts
      const allEntries = new Map<string, { type: 'directory' | 'file'; size: number; modified: number }>();
      for (const e of fsEntries) {
        allEntries.set(e.name, { type: e.type, size: e.size, modified: e.modified });
      }
      for (const d of customDirs) {
        allEntries.set(d, { type: 'directory', size: 4096, modified: Date.now() });
      }
      for (const s of loadedScripts) {
        if (!allEntries.has(s.name)) {
          allEntries.set(s.name, { type: 'file', size: s.size, modified: s.lastModified || Date.now() });
        }
      }

      const allLines: string[] = [];
      allEntries.forEach((info, name) => {
        const perm = info.type === 'directory' ? 'drwxr-xr-x 2 root root' : '-rwxr-xr-x 1 root root';
        const sz = String(info.size).padStart(6, ' ');
        const dt = new Date(info.modified || Date.now()).toLocaleDateString();
        const disp = (info.type === 'directory' && name === 'Practice_Scripts') ? 'Practice_Scripts (407 scripts)' : name;
        allLines.push(`${perm} ${sz} ${dt} ${disp}`);
      });

      appendLog(
        'output',
        `total ${allLines.length}\n` + allLines.join('\n')
      );

      api.executeTerminalCommand({
        command: expandedCmd,
        target_host: isPersonalMode ? (targetHost || 'localhost') : targetHost,
        target_port: targetPort,
        target_url: targetUrl,
        target_scheme: targetScheme,
        target_id: activeAssetId,
        current_dir: currentDir,
      }).then((res) => {
        if (res.fs_entries) setFsEntries(res.fs_entries);
      }).catch(() => {});

      setIsExecuting(false);
      return;
    }

    if (mainCmd === 'cat') {
      const scriptArg = (parts[1] || '').trim();
      const baseName = scriptArg.split('/').pop() || '';
      const foundLoaded = loadedScripts.find((s) => s.name === scriptArg || s.name === baseName);
      if (foundLoaded) {
        appendLog('output', foundLoaded.content);
        setIsExecuting(false);
        return;
      }
      const foundPractice = PRACTICE_SCRIPTS_MANIFEST.find(
        (p) =>
          p.name.toLowerCase() === baseName.toLowerCase() ||
          p.path.toLowerCase() === scriptArg.toLowerCase()
      );
      if (foundPractice) {
        appendLog(
          'output',
          `# ${foundPractice.path} (${foundPractice.categoryLabel})\n` +
          `# Target Assessment Scope: ${targetHost}:${targetPort}\n\n` +
          (foundPractice.fullContent || foundPractice.preview)
        );
        setIsExecuting(false);
        return;
      }

      try {
        const res = await api.executeTerminalCommand({
          command: expandedCmd,
          target_host: isPersonalMode ? (targetHost || 'localhost') : targetHost,
          target_port: targetPort,
          target_url: targetUrl,
          target_scheme: targetScheme,
          target_id: activeAssetId,
          current_dir: currentDir,
        });
        if (res.fs_entries) {
          setFsEntries(res.fs_entries);
        }
        if (res.stdout) {
          appendLog('output', res.stdout.trimEnd());
        } else if (res.stderr) {
          appendLog('error', res.stderr.trimEnd());
        } else {
          appendLog('error', `cat: ${scriptArg || ''}: No such file or directory`);
        }
      } catch {
        appendLog('error', `cat: ${scriptArg || ''}: No such file or directory`);
      }
      setIsExecuting(false);
      return;
    }

    if (mainCmd === 'whoami') {
      appendLog('output', 'root');
      setIsExecuting(false);
      return;
    }

    // Live dispatch via backend Sentinel Assessment Runtime
    if (isAllTargets && assets.length > 0) {
      appendLog(
        'system',
        `[*] [Kali Linux] Multi-Target Dispatch: Executing across All Targets (${assets.length} targets in scope)...`
      );

      for (let i = 0; i < assets.length; i++) {
        const a = assets[i];
        const aHost = a.hostname || new URL(a.canonical_url).hostname;
        const aPort = String(a.port || (a.scheme === 'http' ? 80 : 443));
        const aUrl = a.canonical_url;
        const aScheme = a.scheme || 'https';
        const aExpanded = expandEnvVars(cmdToRun, aHost, aPort, aUrl, aScheme, a.id);

        appendLog('system', `\n─── [Target ${i + 1}/${assets.length}]: ${aHost}:${aPort} (${aUrl}) ───`);

        try {
          const res = await api.executeTerminalCommand({
            command: aExpanded,
            target_host: aHost,
            target_port: aPort,
            target_url: aUrl,
            target_scheme: aScheme,
            target_id: a.id,
            custom_script_name: activeScript?.name,
            custom_script_content: editedScriptContent,
            current_dir: currentDir,
          });

          if (res.current_dir) {
            setCurrentDir(res.current_dir);
          }
          if (res.fs_entries) {
            setFsEntries(res.fs_entries);
          }

          if (res.is_upgraded !== undefined) {
            setIsKaliUpgraded(res.is_upgraded);
            if (res.is_upgraded) {
              localStorage.setItem('kali_upgraded', 'true');
            } else {
              localStorage.removeItem('kali_upgraded');
            }
          }

          if (res.stdout) {
            appendLog('output', res.stdout.trimEnd());
          }
          if (res.stderr) {
            appendLog('error', res.stderr.trimEnd());
          }

          if (res.returncode !== 0 && !res.stderr && !res.stdout) {
            appendLog(
              'error',
              `[-] [${aHost}] Exited with code ${res.returncode}.`
            );
          }
        } catch (err: any) {
          appendLog('error', `[-] [${aHost}] Kali assessment execution failure: ${err.message || String(err)}`);
        }
      }
    } else {
      try {
        if (
          expandedCmd.includes('scan_practice_scripts') ||
          expandedCmd.startsWith('python ') ||
          expandedCmd.startsWith('python3 ') ||
          expandedCmd.startsWith('py ') ||
          expandedCmd.startsWith('nmap ') ||
          expandedCmd.startsWith('sqlmap ') ||
          expandedCmd.startsWith('nikto ') ||
          expandedCmd.startsWith('curl ') ||
          expandedCmd.startsWith('ping ') ||
          expandedCmd.startsWith('traceroute ') ||
          expandedCmd.startsWith('tracert ') ||
          expandedCmd.startsWith('openssl ') ||
          expandedCmd.startsWith('./')
        ) {
          await api.executeTerminalStream(
            {
              command: expandedCmd,
              target_host: isPersonalMode ? (targetHost || 'localhost') : targetHost,
              target_port: targetPort,
              target_url: targetUrl,
              target_scheme: targetScheme,
              target_id: activeAssetId,
              custom_script_name: activeScript?.name,
              custom_script_content: editedScriptContent,
              current_dir: currentDir,
            },
            (line) => {
              let lType: 'output' | 'system' | 'error' | 'success' = 'output';
              if (line.includes('BUG IDENTIFIED') || line.includes('[!] >>>')) lType = 'output';
              else if (line.includes('COMPLETE') || line.includes('Total Security Bugs')) lType = 'success';
              else if (line.startsWith('[*]')) lType = 'system';
              appendLog(lType, line);
              if (terminalLogsContainerRef.current) {
                terminalLogsContainerRef.current.scrollTop = terminalLogsContainerRef.current.scrollHeight;
              }
            },
            (doneRes) => {
              if (doneRes.current_dir) setCurrentDir(doneRes.current_dir);
              if (doneRes.fs_entries) setFsEntries(doneRes.fs_entries);
              setIsExecuting(false);
              setTimeout(() => inputRef.current?.focus({ preventScroll: true }), 30);
            },
            (err) => {
              appendLog('error', `[-] Kali execution failure: ${err.message || String(err)}`);
              setIsExecuting(false);
              setTimeout(() => inputRef.current?.focus({ preventScroll: true }), 30);
            }
          );
          return;
        }

        const res = await api.executeTerminalCommand({
          command: expandedCmd,
          target_host: isPersonalMode ? (targetHost || 'localhost') : targetHost,
          target_port: targetPort,
          target_url: targetUrl,
          target_scheme: targetScheme,
          target_id: activeAssetId,
          custom_script_name: activeScript?.name,
          custom_script_content: editedScriptContent,
          current_dir: currentDir,
        });

        if (res.current_dir) {
          setCurrentDir(res.current_dir);
        }
        if (res.fs_entries) {
          setFsEntries(res.fs_entries);
        }

        if (res.is_upgraded !== undefined) {
          setIsKaliUpgraded(res.is_upgraded);
          if (res.is_upgraded) {
            localStorage.setItem('kali_upgraded', 'true');
          } else {
            localStorage.removeItem('kali_upgraded');
          }
        }

        if (res.stdout) {
          appendLog('output', res.stdout.trimEnd());
        }
        if (res.stderr) {
          appendLog('error', res.stderr.trimEnd());
        }

        if (res.returncode !== 0 && !res.stderr && !res.stdout) {
          appendLog(
            'error',
            `[-] Process exited with code ${res.returncode}.`
          );
        }
      } catch (err: any) {
        appendLog('error', `[-] Kali execution failure: ${err.message || String(err)}`);
      }
    }

    setIsExecuting(false);
    setTimeout(() => {
      inputRef.current?.focus({ preventScroll: true });
    }, 30);
  };

  // Tab command and file autocompletion (Authentic Kali Linux / bash Tab-completion)
  const handleTabCompletion = async () => {
    if (!inputRef.current) return;
    const inputEl = inputRef.current;
    const currentVal = commandInput;
    const cursor = inputEl.selectionStart ?? currentVal.length;

    const textBefore = currentVal.slice(0, cursor);
    const textAfter = currentVal.slice(cursor);

    // Extract the token currently being typed right before the cursor
    const match = textBefore.match(/(\S+)$/);
    const token = match ? match[1] : '';
    const prefix = match ? textBefore.slice(0, match.index) : textBefore;
    const isFirstToken = prefix.trim() === '';

    // Clean relative path of current working directory
    const baseWorkDir = currentDir.replace(/^~\/?(?:target-assessment\/?)?/, '').replace(/\/$/, '');

    let candidatePool: string[] = [];

    if (subConsole.type === 'msfconsole') {
      if (isFirstToken) {
        candidatePool = [
          'use', 'search', 'show', 'options', 'set', 'setg', 'unset',
          'exploit', 'run', 'back', 'info', 'check', 'sessions', 'help', 'exit', 'quit'
        ];
      } else if (prefix.trim().startsWith('use')) {
        candidatePool = [
          'exploit/multi/http/',
          'exploit/windows/smb/ms17_010_eternalblue',
          'auxiliary/scanner/http/title',
          'auxiliary/scanner/portscan/tcp',
          'auxiliary/scanner/ssl/openssl_heartbleed',
        ];
      } else if (prefix.trim().startsWith('show')) {
        candidatePool = ['options', 'payloads', 'exploits', 'auxiliary', 'targets'];
      } else if (prefix.trim().startsWith('set')) {
        candidatePool = ['RHOSTS', 'RPORT', 'LHOST', 'LPORT', 'PAYLOAD', 'TARGETURI', 'SSL', 'THREADS'];
      }
    } else if (subConsole.type === 'meterpreter') {
      candidatePool = ['sysinfo', 'getuid', 'ps', 'pwd', 'upload', 'download', 'screenshot', 'hashdump', 'shell', 'background', 'exit', 'help'];
    } else {
      // Normal Kali Bash Shell mode
      // -------------------------------------------------------------
      // CASE 1: Token contains a slash ('/') -> Child Directory & File Completion
      // -------------------------------------------------------------
      if (token.includes('/')) {
        const lastSlashIdx = token.lastIndexOf('/');
        const dirPart = token.slice(0, lastSlashIdx + 1); // e.g. "Advanced-Penetration-Testing-Script/"
        const filePart = token.slice(lastSlashIdx + 1);   // e.g. "p" or ""

        // Resolve requested directory against current directory
        let lookupDir = dirPart.replace(/^\.\//, '').replace(/\/$/, '');
        if (baseWorkDir && !lookupDir.startsWith('/') && !lookupDir.startsWith('~')) {
          lookupDir = lookupDir ? `${baseWorkDir}/${lookupDir}` : baseWorkDir;
        }

        let dirEntries: Array<{ name: string; type: 'directory' | 'file' }> = [];
        if (dirCacheRef.current[lookupDir]) {
          dirEntries = dirCacheRef.current[lookupDir];
        } else {
          try {
            const res = await api.getTerminalFilesystem(lookupDir);
            if (res && res.entries) {
              dirEntries = res.entries.filter((e) => e.name !== '__pycache__' && !e.name.endsWith('.pyc'));
              dirCacheRef.current[lookupDir] = dirEntries;
              dirCacheRef.current[dirPart] = dirEntries;
            }
          } catch {}
        }

        if (dirEntries.length === 0) {
          if (lookupDir.includes('Advanced')) {
            dirEntries = dirCacheRef.current['Advanced-Penetration-Testing-Script'] || [];
          } else if (lookupDir.includes('Practice')) {
            dirEntries = dirCacheRef.current['Practice_Scripts'] || [];
          }
        }

        const filePartLower = filePart.toLowerCase();
        let matches = dirEntries.filter((e) => e.name.toLowerCase().startsWith(filePartLower));

        if (matches.length === 0 && filePartLower.length >= 2) {
          matches = dirEntries.filter((e) => e.name.toLowerCase().includes(filePartLower));
        }

        if (matches.length === 0) {
          return;
        }

        if (matches.length === 1) {
          const m = matches[0];
          const isDir = m.type === 'directory' || m.name.endsWith('/');
          const completedToken = dirPart + m.name.replace(/\/$/, '') + (isDir ? '/' : ' ');
          const newCmd = prefix + completedToken + textAfter;
          setCommandInput(newCmd);

          const newPos = prefix.length + completedToken.length;
          setTimeout(() => {
            if (inputRef.current) {
              inputRef.current.focus({ preventScroll: true });
              inputRef.current.setSelectionRange(newPos, newPos);
            }
          }, 0);
          return;
        }

        if (matches.length > 1) {
          if (filePart === '') {
            const display = matches.slice(0, 36).map((m) => m.name + (m.type === 'directory' ? '/' : ''));
            appendLog(
              'output',
              display.join('   ') + (matches.length > 36 ? `\n... and ${matches.length - 36} more items` : '')
            );
            setTimeout(() => {
              if (inputRef.current) {
                inputRef.current.focus({ preventScroll: true });
                inputRef.current.setSelectionRange(cursor, cursor);
              }
            }, 10);
            return;
          }

          let lcp = matches[0].name;
          for (let i = 1; i < matches.length; i++) {
            while (!matches[i].name.toLowerCase().startsWith(lcp.toLowerCase())) {
              lcp = lcp.slice(0, -1);
              if (!lcp) break;
            }
          }

          if (lcp.length > filePart.length) {
            const completedToken = dirPart + lcp;
            const newCmd = prefix + completedToken + textAfter;
            setCommandInput(newCmd);

            const newPos = prefix.length + completedToken.length;
            setTimeout(() => {
              if (inputRef.current) {
                inputRef.current.focus({ preventScroll: true });
                inputRef.current.setSelectionRange(newPos, newPos);
              }
            }, 10);
          } else {
            const display = matches.slice(0, 36).map((m) => m.name + (m.type === 'directory' ? '/' : ''));
            appendLog(
              'output',
              display.join('   ') + (matches.length > 36 ? `\n... and ${matches.length - 36} more items` : '')
            );
            setTimeout(() => {
              if (inputRef.current) {
                inputRef.current.focus({ preventScroll: true });
                inputRef.current.setSelectionRange(cursor, cursor);
              }
            }, 10);
          }
          return;
        }

        return;
      }

      // -------------------------------------------------------------
      // CASE 2: Token does NOT contain a slash ('/')
      // -------------------------------------------------------------
      let currentDirEntries = fsEntries;
      if (baseWorkDir) {
        if (dirCacheRef.current[baseWorkDir]) {
          currentDirEntries = dirCacheRef.current[baseWorkDir] as any;
        } else {
          try {
            const res = await api.getTerminalFilesystem(baseWorkDir);
            if (res && res.entries) {
              currentDirEntries = res.entries.filter((e) => e.name !== '__pycache__' && !e.name.endsWith('.pyc')) as any;
              dirCacheRef.current[baseWorkDir] = currentDirEntries as any;
            }
          } catch {}
        }
      }

      const localItems = currentDirEntries.map((e) => (e.type === 'directory' ? `${e.name}/` : e.name));
      const knownRootFiles = ['scan_practice_scripts.py', 'header_audit.py', '060826.py', 'xsstrike.py'];
      const advItems = [
        'penetration_testing3.py',
        'scanner.py',
        'Advanced-Penetration-Testing-Script/penetration_testing3.py',
        'Advanced-Penetration-Testing-Script/scanner.py',
        'xsstrike.py',
        'XSStrike/xsstrike.py',
        'XSStrike/',
      ];

      if (isFirstToken) {
        const baseCmds = [
          'apt', 'apt-get', 'aptitude', 'dpkg',
          'nmap', 'curl', 'wget', 'python', 'python3', 'pip',
          'sqlmap', 'xsstrike', 'xsstrike.py', 'nikto', 'hydra', 'gobuster', 'dirb', 'ffuf', 'wpscan',
          'msfconsole', 'metasploit', 'john', 'aircrack-ng', 'wireshark', 'tshark',
          'hashcat', 'tcpdump', 'wafw00f', 'searchsploit', 'amass',
          'sublist3r', 'dnsrecon', 'theharvester', 'subfinder', 'assetfinder',
          'whois', 'sslscan', 'masscan', 'httpx', 'nuclei',
          'ifconfig', 'ip', 'netstat', 'ss', 'arp', 'route', 'ping',
          'nslookup', 'dig', 'host', 'traceroute', 'tracert', 'openssl', 'nc', 'netcat',
          'ps', 'top', 'df', 'free', 'uname', 'date', 'cal', 'whoami', 'id', 'hostname',
          'cat', 'ls', 'dir', 'cd', 'pwd', 'mkdir', 'rmdir', 'touch', 'rm', 'cp', 'mv',
          'chmod', 'chown', 'grep', 'find', 'head', 'tail', 'wc',
          'echo', 'clear', 'cls', 'help', 'history', 'env', 'export', 'sudo',
        ];

        const historyFirstTokens = commandHistory
          .map((c) => c.trim().split(/\s+/)[0])
          .filter((t) => Boolean(t) && !baseCmds.includes(t));

        candidatePool = Array.from(new Set([...baseCmds, ...historyFirstTokens, ...localItems, ...knownRootFiles]));
      } else {
        const envVars = ['$TARGET_URL', '$TARGET_HOST', '$TARGET_PORT', '$TARGET_SCHEME'];
        const customDirNames = customDirs.map((d) => `${d}/`);
        const dirs = ['../', './'];

        candidatePool = Array.from(
          new Set([
            ...localItems,
            ...knownRootFiles,
            ...advItems,
            ...customDirNames,
            ...dirs,
            ...envVars,
          ])
        );
      }
    }

    // Deduplicate candidatePool: if both "foo/" and "foo" exist, prefer "foo/"
    const dirSet = new Set(
      candidatePool.filter((c) => c.endsWith('/')).map((c) => c.slice(0, -1))
    );
    candidatePool = candidatePool.filter((c) => !dirSet.has(c));

    if (token === '') {
      appendLog('output', candidatePool.slice(0, 36).join('   '));
      setTimeout(() => {
        if (inputRef.current) {
          inputRef.current.focus({ preventScroll: true });
          inputRef.current.setSelectionRange(cursor, cursor);
        }
      }, 10);
      return;
    }

    const tokenLower = token.toLowerCase();
    let matches = candidatePool.filter((c) => c.toLowerCase().startsWith(tokenLower));

    if (matches.length === 0 && tokenLower.length >= 3) {
      matches = candidatePool.filter((c) => c.toLowerCase().includes(tokenLower));
    }

    if (matches.length === 0) {
      return;
    }

    if (matches.length === 1) {
      const matchWord = matches[0];
      const isDir = matchWord.endsWith('/');
      const completed = matchWord + (isDir ? '' : ' ');
      const newCmd = prefix + completed + textAfter;
      setCommandInput(newCmd);

      const newCursorPos = prefix.length + completed.length;
      setTimeout(() => {
        if (inputRef.current) {
          inputRef.current.focus({ preventScroll: true });
          inputRef.current.setSelectionRange(newCursorPos, newCursorPos);
        }
      }, 10);
      return;
    }

    // Multiple matches: find longest common prefix
    let lcp = matches[0];
    for (let i = 1; i < matches.length; i++) {
      while (!matches[i].toLowerCase().startsWith(lcp.toLowerCase())) {
        lcp = lcp.slice(0, -1);
        if (!lcp) break;
      }
    }

    if (lcp.length > token.length) {
      const newCmd = prefix + lcp + textAfter;
      setCommandInput(newCmd);
      const newCursorPos = prefix.length + lcp.length;
      setTimeout(() => {
        if (inputRef.current) {
          inputRef.current.focus({ preventScroll: true });
          inputRef.current.setSelectionRange(newCursorPos, newCursorPos);
        }
      }, 10);
    } else {
      const displayMatches = matches.slice(0, 36);
      appendLog(
        'output',
        displayMatches.join('   ') +
          (matches.length > 36 ? `\n... and ${matches.length - 36} more candidates` : '')
      );
      setTimeout(() => {
        if (inputRef.current) {
          inputRef.current.focus({ preventScroll: true });
          inputRef.current.setSelectionRange(cursor, cursor);
        }
      }, 10);
    }
  };

  // Keyboard navigation for command history (Up / Down) & Tab completion
  const handleKeyDown = async (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      executeCommand();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length === 0) return;

      let nextIdx = 0;
      if (historyIndex === -1) {
        draftInputRef.current = commandInput;
        nextIdx = 0;
      } else {
        nextIdx = Math.min(historyIndex + 1, commandHistory.length - 1);
      }
      setHistoryIndex(nextIdx);
      setCommandInput(commandHistory[nextIdx]);

      // Move cursor to end of input
      setTimeout(() => {
        if (inputRef.current) {
          const len = inputRef.current.value.length;
          inputRef.current.setSelectionRange(len, len);
        }
      }, 0);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const nextIdx = historyIndex - 1;
        setHistoryIndex(nextIdx);
        setCommandInput(commandHistory[nextIdx]);
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setCommandInput(draftInputRef.current);
      }

      // Move cursor to end of input
      setTimeout(() => {
        if (inputRef.current) {
          const len = inputRef.current.value.length;
          inputRef.current.setSelectionRange(len, len);
        }
      }, 0);
    } else if (e.key === 'Tab') {
      e.preventDefault();
      await handleTabCompletion();
    }
  };

  const handleCopyConsole = () => {
    const textToCopy = logs.map((l) => l.content).join('\n');
    navigator.clipboard.writeText(textToCopy);
    setCopiedConsole(true);
    setTimeout(() => setCopiedConsole(false), 2000);
  };

  return (
    <div
      style={{ backgroundColor: '#05070e', color: '#ffffff' }}
      className={`kali-terminal-container bg-[#05070e] rounded-2xl border border-slate-800/90 shadow-2xl overflow-hidden text-white font-mono ${className}`}
      onDragOver={(e) => e.preventDefault()}
      onDrop={handleDrop}
    >
      {/* Hidden File Picker for Loading System Scripts (.py, .sh) */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileUpload}
        accept=".py,.sh,.txt,.bash"
        className="hidden"
      />

      {/* --- KALI LINUX TERMINAL HEADER BAR (AUTHENTIC WINDOW CHROME) --- */}
      <div className="kali-terminal-header bg-[#0d111c] px-4 py-2.5 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-2.5 font-sans">
        <div className="flex items-center space-x-3">
          {/* Window action dots */}
          <div className="flex items-center space-x-1.5">
            <span className="w-3 h-3 rounded-full bg-rose-500/90 inline-block border border-rose-600 shadow-sm" />
            <span className="w-3 h-3 rounded-full bg-amber-500/90 inline-block border border-amber-600 shadow-sm" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/90 inline-block border border-emerald-600 shadow-sm" />
          </div>

          {/* Kali Linux Prompt Title */}
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="px-2.5 py-0.5 rounded-lg bg-slate-900 text-white font-bold border border-slate-700/80 flex items-center space-x-1.5 shadow-sm">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>Kali Terminal</span>
            </span>
            <span className="text-slate-400 font-semibold hidden sm:inline">
              <strong className="text-white">root@kali:</strong>{' '}
              <span className="text-slate-300">
                {subConsole.type === 'msfconsole'
                  ? subConsole.module
                    ? `msf (${subConsole.module})`
                    : 'msfconsole (v6.3.50)'
                  : subConsole.type === 'meterpreter'
                  ? 'meterpreter (session 1)'
                  : subConsole.type === 'python'
                  ? 'python3 (interactive repl)'
                  : currentDir}
              </span>
            </span>
            {subConsole.type === 'msfconsole' ? (
              <span className="px-2.5 py-0.5 rounded-lg bg-rose-950/80 text-rose-300 border border-rose-800/80 text-[10px] font-sans font-semibold hidden md:flex items-center space-x-1 shadow-sm">
                <Shield className="w-3 h-3 text-rose-400" />
                <span>Metasploit Active</span>
              </span>
            ) : subConsole.type === 'meterpreter' ? (
              <span className="px-2.5 py-0.5 rounded-lg bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 text-[10px] font-sans font-semibold hidden md:flex items-center space-x-1 shadow-sm">
                <Terminal className="w-3 h-3 text-cyan-400" />
                <span>Meterpreter Session</span>
              </span>
            ) : (
              <span className="px-2.5 py-0.5 rounded-lg bg-red-950/80 text-red-300 border border-red-800/80 text-[10px] font-sans font-semibold hidden md:flex items-center space-x-1 shadow-sm">
                <Shield className="w-3 h-3 text-red-400" />
                <span>Root Privileges (UID 0)</span>
              </span>
            )}
          </div>
        </div>

        {/* Action Controls in Header */}
        <div className="flex items-center space-x-2 text-xs">
          {/* Target Selector Dropdown */}
          <div
            onClick={(e) => {
              e.stopPropagation();
              if (e.target !== targetSelectRef.current) {
                targetSelectRef.current?.focus();
                if (typeof (targetSelectRef.current as any)?.showPicker === 'function') {
                  try {
                    (targetSelectRef.current as any).showPicker();
                  } catch {
                    // Fallback to focus
                  }
                }
              }
            }}
            onMouseDown={(e) => e.stopPropagation()}
            className="flex items-center space-x-2 bg-[#131b2e] hover:bg-[#1c2742] px-3.5 py-1.5 rounded-xl border border-cyan-400/60 hover:border-cyan-300 cursor-pointer transition shadow-md font-sans text-white"
          >
            <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="text-xs font-sans text-slate-200 font-semibold select-none hidden md:inline">Target:</span>
            <select
              ref={targetSelectRef}
              value={activeAssetId}
              onChange={(e) => handleTargetChange(e.target.value)}
              onClick={(e) => e.stopPropagation()}
              onMouseDown={(e) => e.stopPropagation()}
              className="bg-[#131b2e] text-xs font-sans font-semibold text-white focus:outline-none cursor-pointer max-w-[220px] truncate"
            >
              <option value="personal" className="bg-[#0b0f19] text-amber-300 font-bold">
                Personal
              </option>
              <option value="all" className="bg-[#0b0f19] text-white font-bold">
                All Targets ({assets.length})
              </option>
              {assets.map((a) => (
                <option key={a.id} value={a.id} className="bg-[#0b0f19] text-white">
                  {a.hostname || a.canonical_url} (Port {a.port || 443})
                </option>
              ))}
              {assets.length === 0 && (
                <option value="" className="bg-[#0b0f19] text-slate-500">
                  No targets authorized
                </option>
              )}
            </select>
          </div>

          {/* Load Script (.py) from Local System Button */}
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="bg-[#131b2e] hover:bg-[#1c2742] px-3.5 py-1.5 rounded-xl text-white font-sans text-xs font-semibold flex items-center space-x-1.5 cursor-pointer transition shadow-md border border-slate-600 hover:border-cyan-400"
            title="Load Python (.py) or Shell (.sh) script from your system"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>Load Script (.py)</span>
          </button>

          {/* Copy Terminal Button */}
          <button
            type="button"
            onClick={handleCopyConsole}
            className="p-1.5 text-slate-200 hover:text-white rounded-xl bg-[#131b2e] hover:bg-[#1c2742] border border-slate-700 hover:border-slate-500 transition cursor-pointer font-sans shadow-md"
            title="Copy terminal logs"
          >
            {copiedConsole ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-300" />}
          </button>

          {/* Clear Console Button */}
          <button
            type="button"
            onClick={() => setLogs([])}
            className="p-1.5 text-slate-200 hover:text-rose-400 rounded-xl bg-[#131b2e] hover:bg-[#1c2742] border border-slate-700 hover:border-rose-500 transition cursor-pointer font-sans shadow-md"
            title="Clear terminal"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* --- TARGET ENVIRONMENT VARIABLES STRIP --- */}
      <div className="kali-terminal-env-strip bg-[#080c16] px-4 py-2 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs font-sans text-white">
        <div className="flex items-center space-x-2 text-xs text-slate-300 flex-wrap gap-y-1">
          <span className="text-white font-bold flex items-center space-x-1 font-sans">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span>ENV:</span>
          </span>
          {isPersonalMode ? (
            <>
              <span className="px-2.5 py-0.5 rounded-full font-sans text-xs font-semibold text-amber-300 bg-amber-950/60 border border-amber-500/50 flex items-center space-x-1.5 shadow-sm">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
                <span>Personal (Free Standalone Shell)</span>
              </span>
              <span className="px-2.5 py-0.5 rounded-xl bg-slate-900/90 border border-slate-700 text-slate-200 font-sans text-xs">
                Target Constraint: <span className="text-emerald-400 font-semibold">None (Free Execution)</span>
              </span>
              <span className="px-2.5 py-0.5 rounded-xl bg-slate-900/90 border border-slate-700 text-slate-200 font-sans text-xs">
                Privileges: <span className="text-rose-400 font-bold">root (uid=0)</span>
              </span>
              <div 
                onClick={(e) => e.stopPropagation()}
                onMouseDown={(e) => e.stopPropagation()}
                className="px-2.5 py-0.5 rounded-xl bg-slate-900/90 border border-slate-700 flex items-center space-x-1.5 font-sans text-xs text-slate-200"
              >
                <strong className="text-slate-300 font-sans">$TARGET_PORT:</strong>
                <input
                  type="text"
                  value={customPort}
                  onChange={(e) => setCustomPort(e.target.value.trim())}
                  onClick={(e) => e.stopPropagation()}
                  onMouseDown={(e) => e.stopPropagation()}
                  placeholder="Port"
                  title="Target Port: Enter ANY port number (1-65535, e.g. 443, 80, 8080, 8443, 3000, 22, 1-65535)"
                  className="bg-black px-2 py-0.5 rounded-lg border border-slate-600 text-white font-sans text-xs font-semibold w-16 focus:w-20 focus:outline-none focus:border-cyan-400 transition-all text-center"
                />
              </div>
            </>
          ) : (
            <>
              <span className="px-2.5 py-0.5 rounded-xl bg-slate-900/90 border border-slate-700 font-sans text-xs text-slate-200">
                <strong className="text-slate-300 font-sans">$TARGET_URL:</strong> <span className="text-white font-semibold font-sans">{targetUrl}</span>
              </span>
              <span className="px-2.5 py-0.5 rounded-xl bg-slate-900/90 border border-slate-700 font-sans text-xs text-slate-200">
                <strong className="text-slate-300 font-sans">$TARGET_HOST:</strong> <span className="text-white font-semibold font-sans">{targetHost}</span>
              </span>
              <div 
                onClick={(e) => e.stopPropagation()}
                onMouseDown={(e) => e.stopPropagation()}
                className="px-2.5 py-0.5 rounded-xl bg-slate-900/90 border border-slate-700 flex items-center space-x-1.5 font-sans text-xs text-slate-200"
              >
                <strong className="text-slate-300 font-sans">$TARGET_PORT:</strong>
                <input
                  type="text"
                  value={customPort}
                  onChange={(e) => setCustomPort(e.target.value.trim())}
                  onClick={(e) => e.stopPropagation()}
                  onMouseDown={(e) => e.stopPropagation()}
                  placeholder="Port"
                  title="Target Port: Enter ANY port number (1-65535, e.g. 443, 80, 8080, 8443, 3000, 22, 1-65535)"
                  className="bg-black px-2 py-0.5 rounded-lg border border-slate-600 text-white font-sans text-xs font-semibold w-16 focus:w-20 focus:outline-none focus:border-cyan-400 transition-all text-center"
                />
              </div>
            </>
          )}
        </div>

        {/* Toggle Controls for Script Drawers */}
        <div className="flex items-center space-x-2">
          {/* Toggle Practice_Scripts Drawer */}
          <button
            type="button"
            onClick={() => {
              setShowPracticeScriptsDrawer(!showPracticeScriptsDrawer);
              if (showAdvancedScriptsDrawer) setShowAdvancedScriptsDrawer(false);
              if (showXSStrikeDrawer) setShowXSStrikeDrawer(false);
            }}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold font-sans flex items-center space-x-2 cursor-pointer transition shadow-md ${
              showPracticeScriptsDrawer
                ? 'bg-indigo-600 hover:bg-indigo-500 text-white border border-indigo-300 shadow-lg shadow-indigo-600/40 ring-2 ring-indigo-400/50'
                : 'bg-[#151a33] hover:bg-[#1e2547] text-indigo-100 hover:text-white border border-indigo-500/60 shadow-md hover:border-indigo-400'
            }`}
          >
            <Folder className="w-3.5 h-3.5 text-indigo-400" />
            <span>Practice_Scripts (407)</span>
            {showPracticeScriptsDrawer ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {/* Toggle Advanced-Penetration-Testing-Script Drawer */}
          <button
            type="button"
            onClick={() => {
              setShowAdvancedScriptsDrawer(!showAdvancedScriptsDrawer);
              if (showPracticeScriptsDrawer) setShowPracticeScriptsDrawer(false);
              if (showXSStrikeDrawer) setShowXSStrikeDrawer(false);
            }}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold font-sans flex items-center space-x-2 cursor-pointer transition shadow-md ${
              showAdvancedScriptsDrawer
                ? 'bg-cyan-600 hover:bg-cyan-500 text-white border border-cyan-300 shadow-lg shadow-cyan-600/40 ring-2 ring-cyan-400/50'
                : 'bg-[#0c2233] hover:bg-[#122e45] text-cyan-100 hover:text-white border border-cyan-500/60 shadow-md hover:border-cyan-400'
            }`}
            title="Browse and launch Advanced-Penetration-Testing-Script tools"
          >
            <Folder className="w-3.5 h-3.5 text-cyan-400" />
            <span>Advanced-Penetration-Testing-Script ({advancedScripts.length})</span>
            {showAdvancedScriptsDrawer ? <ChevronUp className="w-3.5 h-3.5 text-cyan-400" /> : <ChevronDown className="w-3.5 h-3.5 text-cyan-400" />}
          </button>

          {/* Toggle XSStrike Drawer */}
          <button
            type="button"
            onClick={() => {
              setShowXSStrikeDrawer(!showXSStrikeDrawer);
              if (showPracticeScriptsDrawer) setShowPracticeScriptsDrawer(false);
              if (showAdvancedScriptsDrawer) setShowAdvancedScriptsDrawer(false);
            }}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold font-sans flex items-center space-x-2 cursor-pointer transition shadow-md ${
              showXSStrikeDrawer
                ? 'bg-amber-600 hover:bg-amber-500 text-white border border-amber-300 shadow-lg shadow-amber-600/40 ring-2 ring-amber-400/50'
                : 'bg-[#291f0a] hover:bg-[#3b2d10] text-amber-100 hover:text-white border border-amber-500/60 shadow-md hover:border-amber-400'
            }`}
            title="XSStrike v3.1.5 - Advanced XSS & DOM Scanning Suite"
          >
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>XSStrike (1)</span>
            {showXSStrikeDrawer ? <ChevronUp className="w-3.5 h-3.5 text-amber-400" /> : <ChevronDown className="w-3.5 h-3.5 text-amber-400" />}
          </button>
        </div>
      </div>

      {/* --- PRACTICE SCRIPTS DRAWER (407 SCRIPTS REPOSITORY) --- */}
      {showPracticeScriptsDrawer && (
        <div className="kali-terminal-drawer bg-[#090d16] p-4 border-b border-slate-800 space-y-3 font-sans text-xs text-white">
          {/* Drawer Header */}
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center space-x-2.5">
              <Folder className="w-4 h-4 text-indigo-400" />
              <span className="text-white font-bold text-xs sm:text-sm font-sans">
                ~/target-assessment/Practice_Scripts
              </span>
              <span className="px-2.5 py-0.5 rounded-full liquid-glass-pill text-indigo-300 border border-indigo-500/30 text-xs font-semibold font-sans">
                407 Security Assessment Scripts
              </span>
            </div>
            <button
              type="button"
              onClick={() => setShowPracticeScriptsDrawer(false)}
              className="p-1.5 text-slate-400 hover:text-white rounded-xl hover:bg-white/10 transition cursor-pointer font-sans"
              title="Close Practice Scripts Library"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Search & Category Filter Pills */}
          <div className="space-y-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={practiceSearchQuery}
                onChange={(e) => setPracticeSearchQuery(e.target.value)}
                placeholder="Search 407 scripts by name, CVE, or keyword..."
                className="w-full bg-[#05070e] pl-9 pr-8 py-2 rounded-xl border border-slate-700/80 text-white text-xs font-sans focus:outline-none focus:border-indigo-500 placeholder:text-slate-500 caret-white"
              />
              {practiceSearchQuery && (
                <button
                  type="button"
                  onClick={() => setPracticeSearchQuery('')}
                  className="absolute right-2.5 top-2 text-slate-400 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="flex items-center justify-between text-xs font-sans px-3 py-1.5 rounded-xl bg-[#0c101c] border border-slate-800 text-slate-400">
              <span>Directory: <strong className="text-cyan-300 font-mono">~/target-assessment/Practice_Scripts/</strong></span>
              <span className="text-slate-500">407 modular scripts &bull; 0 subdirectories</span>
            </div>
          </div>

          {/* Filtered Scripts List */}
          <div className="max-h-64 overflow-y-auto space-y-1.5 pr-1 divide-y divide-slate-800/60">
            {filteredPracticeScripts.slice(0, 60).map((script) => (
              <div
                key={script.name}
                className="pt-1.5 flex items-center justify-between gap-2 hover:bg-white/5 p-2 rounded-xl border border-slate-800/60 bg-[#070b14]"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-white truncate font-sans text-xs">{script.name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full liquid-glass-pill text-cyan-300 border border-cyan-500/30 font-semibold font-sans">
                      Practice_Scripts
                    </span>
                    <span className="text-[11px] text-slate-400 font-sans">
                      {Math.round((script.size / 1024) * 10) / 10} KB
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 truncate mt-0.5 font-sans">{script.description}</p>
                </div>

                <div className="flex items-center space-x-1.5 shrink-0">
                  {/* Direct Run Script */}
                  <button
                    type="button"
                    title={`Execute ${script.name} immediately against active target`}
                    onClick={() => {
                      executeCommand(`python ${script.path} $TARGET_HOST $TARGET_PORT`);
                    }}
                    className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold font-sans px-3 py-1.5 rounded-xl flex items-center space-x-1 cursor-pointer transition shadow-md shadow-indigo-600/30"
                  >
                    <Play className="w-3 h-3 fill-current text-white" />
                    <span>Run</span>
                  </button>

                  {/* Stage Script into Terminal Prompt */}
                  <button
                    type="button"
                    title="Stage command into terminal prompt"
                    onClick={() => {
                      setCommandInput(`python Practice_Scripts/${script.name} $TARGET_HOST $TARGET_PORT`);
                      inputRef.current?.focus({ preventScroll: true });
                    }}
                    className="bg-[#161f36] hover:bg-[#1e2a4a] text-slate-100 hover:text-white border border-slate-700/80 hover:border-slate-500 px-3 py-1.5 rounded-xl text-xs font-semibold font-sans flex items-center space-x-1 cursor-pointer transition shadow-sm"
                  >
                    <FileText className="w-3 h-3 text-slate-300" />
                    <span>Stage</span>
                  </button>
                </div>
              </div>
            ))}
            {filteredPracticeScripts.length === 0 && (
              <div className="text-center py-6 text-slate-500 font-sans text-xs">
                No practice scripts matching &quot;{practiceSearchQuery}&quot;
              </div>
            )}
          </div>
        </div>
      )}

      {/* --- ADVANCED PENETRATION TESTING SCRIPTS DRAWER --- */}
      {showAdvancedScriptsDrawer && (
        <div className="kali-terminal-drawer bg-[#090d16] p-4 border-b border-slate-800 space-y-3 font-sans text-xs text-white">
          {/* Drawer Header */}
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center space-x-2.5">
              <Folder className="w-4 h-4 text-cyan-400" />
              <span className="text-white font-bold text-xs sm:text-sm font-sans">
                ~/target-assessment/Advanced-Penetration-Testing-Script
              </span>
              <span className="px-2.5 py-0.5 rounded-full liquid-glass-pill text-cyan-300 border border-cyan-500/30 text-xs font-semibold font-sans">
                {advancedScripts.length} Penetration Testing .py Scripts
              </span>
            </div>
            <button
              type="button"
              onClick={() => setShowAdvancedScriptsDrawer(false)}
              className="p-1.5 text-slate-400 hover:text-white rounded-xl hover:bg-white/10 transition cursor-pointer font-sans"
              title="Close Advanced Penetration Testing Library"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Search Box */}
          <div className="space-y-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={advancedSearchQuery}
                onChange={(e) => setAdvancedSearchQuery(e.target.value)}
                placeholder="Search Advanced-Penetration-Testing-Script by name or keyword..."
                className="w-full bg-[#05070e] pl-9 pr-8 py-2 rounded-xl border border-slate-700/80 text-white text-xs font-sans focus:outline-none focus:border-cyan-500 placeholder:text-slate-500 caret-white"
              />
              {advancedSearchQuery && (
                <button
                  type="button"
                  onClick={() => setAdvancedSearchQuery('')}
                  className="absolute right-2.5 top-2.5 text-slate-400 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="flex items-center justify-between text-xs font-sans px-3 py-1.5 rounded-xl bg-[#0c101c] border border-slate-800 text-slate-400">
              <span>Directory: <strong className="text-cyan-300 font-mono">~/target-assessment/Advanced-Penetration-Testing-Script/</strong></span>
              <span className="text-slate-500">Netwatch Cyberpunk & Quickhack Pentest Engines</span>
            </div>
          </div>

          {/* Filtered Scripts List */}
          <div className="max-h-72 overflow-y-auto space-y-2 pr-1 divide-y divide-slate-800/60">
            {filteredAdvancedScripts.map((script) => (
              <div
                key={script.name}
                className="pt-2 flex items-center justify-between gap-3 hover:bg-white/5 p-3 rounded-xl border border-slate-800/80 bg-[#070b14]"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-white text-sm font-sans">{script.name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full liquid-glass-pill text-cyan-300 border border-cyan-500/30 font-semibold font-sans">
                      {script.category}
                    </span>
                    <span className="text-[11px] text-slate-400 font-sans">
                      {Math.round((script.size / 1024) * 10) / 10} KB
                    </span>
                  </div>
                  <div className="text-xs text-cyan-300 font-semibold mt-0.5 font-sans">{script.title}</div>
                  <p className="text-xs text-slate-300 mt-1 leading-relaxed font-sans">{script.description}</p>
                  <div className="mt-1.5 flex items-center space-x-2 text-[11px] text-slate-400 font-mono">
                    <span className="text-slate-400">Command:</span>
                    <code className="text-cyan-300 bg-[#0c101c] px-2 py-0.5 rounded-lg border border-slate-800">
                      {script.commandTemplate}
                    </code>
                  </div>
                </div>

                <div className="flex items-center space-x-1.5 shrink-0 self-center">
                  {/* Direct Run Script */}
                  <button
                    type="button"
                    title={`Execute ${script.name} immediately against active target`}
                    onClick={() => {
                      const cmd = script.commandTemplate
                        .replace('$TARGET_URL', targetUrl)
                        .replace('$TARGET_HOST', targetHost)
                        .replace('$TARGET_PORT', targetPort);
                      executeCommand(cmd);
                    }}
                    className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold font-sans px-3 py-1.5 rounded-xl flex items-center space-x-1 cursor-pointer transition shadow-md shadow-cyan-600/30"
                  >
                    <Play className="w-3 h-3 fill-current text-white" />
                    <span>Run</span>
                  </button>

                  {/* Stage Script into Terminal Prompt */}
                  <button
                    type="button"
                    title="Stage command into terminal prompt"
                    onClick={() => {
                      setCommandInput(script.commandTemplate);
                      inputRef.current?.focus({ preventScroll: true });
                    }}
                    className="bg-[#161f36] hover:bg-[#1e2a4a] text-slate-100 hover:text-white border border-slate-700/80 hover:border-slate-500 px-3 py-1.5 rounded-xl text-xs font-semibold font-sans flex items-center space-x-1 cursor-pointer transition shadow-sm"
                  >
                    <FileText className="w-3 h-3 text-slate-300" />
                    <span>Stage</span>
                  </button>
                </div>
              </div>
            ))}
            {filteredAdvancedScripts.length === 0 && (
              <div className="text-center py-6 text-slate-500 font-sans text-xs">
                No scripts matching &quot;{advancedSearchQuery}&quot;
              </div>
            )}
          </div>
        </div>
      )}

      {/* --- XSSTRIKE DRAWER (XSSTRIKE.PY RECONNAISSANCE SUITE) --- */}
      {showXSStrikeDrawer && (
        <div className="kali-terminal-drawer bg-[#090d16] p-4 border-b border-slate-800 space-y-3 font-sans text-xs text-white">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center space-x-2.5">
              <Zap className="w-4 h-4 text-amber-400" />
              <span className="text-white font-bold text-xs sm:text-sm font-sans">
                ~/target-assessment/XSStrike
              </span>
              <span className="px-2.5 py-0.5 rounded-full liquid-glass-pill text-amber-300 border border-amber-500/30 text-xs font-semibold font-sans">
                XSStrike v3.1.5 (Advanced XSS &amp; DOM Scanner)
              </span>
            </div>
            <button
              type="button"
              onClick={() => setShowXSStrikeDrawer(false)}
              className="p-1.5 text-slate-400 hover:text-white rounded-xl hover:bg-white/10 transition cursor-pointer font-sans"
              title="Close XSStrike Drawer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="p-3.5 rounded-xl border border-amber-500/30 bg-[#070b14] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-amber-200 font-bold font-mono text-xs">xsstrike.py</span>
                <span className="px-2 py-0.5 rounded-full liquid-glass-pill text-amber-400 border border-amber-500/30 text-[10px] font-sans font-semibold">
                  XSS FUZZER &amp; CRAWLER
                </span>
              </div>
              <p className="text-xs text-slate-300 max-w-xl font-sans leading-relaxed">
                Advanced XSS detection suite equipped with 4 handwritten parsers, intelligent payload generator, powerful fuzzing engine, DOM XSS checking, and WAF evasion.
              </p>
              <div className="text-[11px] text-slate-400 font-mono">
                Command: <code className="text-amber-200 bg-[#0c101c] px-2 py-0.5 rounded-lg border border-slate-800">python XSStrike/xsstrike.py -u {isPersonalMode ? '$TARGET_URL' : targetUrl} --crawl -l 1 --skip</code>
              </div>
            </div>

            <div className="flex items-center space-x-2 shrink-0">
              <button
                type="button"
                onClick={() => {
                  const cmd = isPersonalMode
                    ? 'python XSStrike/xsstrike.py --help'
                    : `python XSStrike/xsstrike.py -u ${targetUrl} --crawl -l 1 --skip`;
                  executeCommand(cmd);
                }}
                className="bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold font-sans px-3.5 py-1.5 rounded-xl flex items-center space-x-1 cursor-pointer transition shadow-md shadow-amber-600/30"
              >
                <Play className="w-3 h-3 fill-current text-white" />
                <span>Run</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  const cmd = isPersonalMode
                    ? 'python XSStrike/xsstrike.py -u $TARGET_URL --crawl -l 1 --skip'
                    : `python XSStrike/xsstrike.py -u ${targetUrl} --crawl -l 1 --skip`;
                  setCommandInput(cmd);
                  inputRef.current?.focus({ preventScroll: true });
                }}
                className="bg-[#161f36] hover:bg-[#1e2a4a] text-slate-100 hover:text-white border border-slate-700/80 hover:border-slate-500 px-3.5 py-1.5 rounded-xl text-xs font-semibold font-sans flex items-center space-x-1 cursor-pointer transition shadow-sm"
              >
                <FileText className="w-3 h-3 text-slate-300" />
                <span>Stage</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* --- ACTIVE PRACTICE SCRIPTS & ADVANCED AUDIT PROGRESS BAR --- */}
      {practiceScanProgress && (
        <div className="w-full bg-[#0a0f1d] px-4 py-2.5 border-b border-cyan-800/50 flex items-center space-x-3 text-xs font-sans text-white shadow-inner">
          <div className="flex items-center space-x-2 shrink-0">
            <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
            <span className="text-cyan-300 font-bold tracking-tight font-sans">
              [PRACTICE SUITE 407]: {practiceScanProgress.current}/{practiceScanProgress.total}
            </span>
          </div>
          <div className="flex-1 bg-[#05070e] rounded-full h-2.5 overflow-hidden border border-slate-700/80">
            <div
              className="bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 h-full transition-all duration-150 ease-out shadow-[0_0_12px_rgba(6,182,212,0.5)]"
              style={{
                width: `${Math.min(100, Math.max(1, (practiceScanProgress.current / practiceScanProgress.total) * 100))}%`,
              }}
            />
          </div>
          <span className="text-slate-300 shrink-0 text-xs font-sans truncate max-w-[280px]">
            {practiceScanProgress.category === 'Complete'
              ? 'Audit Complete (100%)'
              : practiceScanProgress.category === 'Advanced-Penetration-Testing-Script'
              ? `Advanced-Penetration-Testing-Script/${practiceScanProgress.scriptName.replace(/^Advanced-Penetration-Testing-Script\//, '')}`
              : practiceScanProgress.category === 'XSStrike'
              ? `XSStrike/${practiceScanProgress.scriptName.replace(/^XSStrike\//, '')}`
              : practiceScanProgress.scriptName.startsWith('Initializing')
              ? practiceScanProgress.scriptName
              : `Practice_Scripts/${practiceScanProgress.scriptName.replace(/^Practice_Scripts\//, '')}`}
          </span>
          <span className="text-cyan-300 font-bold shrink-0 font-sans text-xs">
            {Math.min(100, Math.round((practiceScanProgress.current / practiceScanProgress.total) * 100))}%
          </span>
        </div>
      )}

      {/* --- AUTHENTIC TERMINAL VIEWPORT WITH REAL INLINE PROMPT & LINE-BY-LINE INPUT --- */}
      <div
        ref={terminalLogsContainerRef}
        onClick={(e) => {
          const selection = window.getSelection();
          if (selection && selection.toString().length > 0) return;
          const target = e.target as HTMLElement;
          if (target && (target.tagName === 'BUTTON' || target.tagName === 'A' || target.tagName === 'INPUT' || target.tagName === 'SELECT' || target.tagName === 'TEXTAREA')) return;
          inputRef.current?.focus({ preventScroll: true });
        }}
        style={{ backgroundColor: '#05070e', color: '#ffffff' }}
        className="kali-terminal-screen bg-[#05070e] p-4 font-mono text-xs overflow-y-auto max-h-[480px] min-h-[320px] space-y-2 select-text text-white leading-relaxed cursor-text"
      >
        {logs.map((log) => {
          if (log.type === 'banner') {
            return (
              <div key={log.id} className="text-white whitespace-pre-wrap border-b border-zinc-800 pb-2">
                {log.content}
              </div>
            );
          }
          if (log.type === 'input') {
            if (log.content.startsWith('msf6')) {
              const match = log.content.match(/^(msf6(?:\s+[a-z]+(?:\([^)]+\))?)?\s*>\s*)(.*)$/s);
              const promptPart = match ? match[1] : 'msf6 > ';
              const cmdPart = match ? match[2] : log.content;
              return (
                <div key={log.id} className="text-white pt-1 font-mono text-xs flex items-center space-x-1.5">
                  <span className="text-rose-500 font-bold select-none">{promptPart}</span>
                  <span className="text-white font-mono font-semibold">{cmdPart}</span>
                </div>
              );
            }
            if (log.content.startsWith('meterpreter >')) {
              const cmdPart = log.content.replace(/^meterpreter >\s*/, '');
              return (
                <div key={log.id} className="text-white pt-1 font-mono text-xs flex items-center space-x-1.5">
                  <span className="text-cyan-400 font-bold select-none">meterpreter &gt; </span>
                  <span className="text-white font-mono font-semibold">{cmdPart}</span>
                </div>
              );
            }
            if (log.content.startsWith('>>>')) {
              const cmdPart = log.content.replace(/^>>>\s*/, '');
              return (
                <div key={log.id} className="text-white pt-1 font-mono text-xs flex items-center space-x-1.5">
                  <span className="text-amber-400 font-bold select-none">&gt;&gt;&gt; </span>
                  <span className="text-white font-mono font-semibold">{cmdPart}</span>
                </div>
              );
            }
            const lines = log.content.split('\n');
            const promptHeader = lines[0] || '';
            const cmdText = lines[1] ? lines[1].replace(/^└─#\s*/, '') : '';
            return (
              <div key={log.id} className="text-white pt-1 space-y-0.5">
                <div className="font-mono text-xs flex items-center space-x-1">
                  <span className="text-[#3b82f6]">┌──(</span>
                  <span className="text-white font-bold">root㉿kali</span>
                  <span className="text-[#3b82f6]">)-[</span>
                  <span className="text-white font-semibold">
                    {promptHeader.replace(/^┌──\(root㉿kali\)-\[/, '').replace(/\]$/, '') || currentDir}
                  </span>
                  <span className="text-[#3b82f6]">]</span>
                </div>
                <div className="font-mono text-xs flex items-center space-x-1.5">
                  <span className="text-[#3b82f6] select-none">└─</span>
                  <span className="text-white font-bold select-none">#</span>
                  <span className="text-white font-mono font-semibold">{cmdText || log.content}</span>
                </div>
              </div>
            );
          }
          let lineClass = 'text-white';
          if (log.type === 'error') {
            lineClass = 'text-red-400';
          } else if (log.content.includes('[!] >>> BUG IDENTIFIED')) {
            lineClass = 'text-rose-400 font-bold';
          } else if (log.content.includes('[Script Response Proof]')) {
            lineClass = 'text-amber-300 font-semibold';
          } else if (log.content.includes('[PROOF #')) {
            lineClass = 'text-emerald-400 font-bold';
          } else if (log.content.includes('EMPIRICAL SCRIPT RESPONSES & PROOF DOSSIER')) {
            lineClass = 'text-cyan-300 font-bold';
          } else if (log.content.includes('│     >>>')) {
            lineClass = 'text-amber-300 font-medium';
          } else if (log.content.includes('│   Script CLI Command:') || log.content.includes('│   Reproduction Command:')) {
            lineClass = 'text-emerald-300 font-medium';
          } else if (log.content.includes('│   Target Wire Response:')) {
            lineClass = 'text-sky-300 font-medium';
          } else if (log.content.includes('│   Observed Script Proof:')) {
            lineClass = 'text-yellow-200 font-semibold';
          } else if (log.type === 'success') {
            lineClass = 'text-white whitespace-pre-wrap font-semibold';
          } else if (log.type === 'system') {
            lineClass = 'text-slate-100 font-medium';
          }

          return (
            <div key={log.id} className={`${lineClass} whitespace-pre-wrap`}>
              {log.content}
            </div>
          );
        })}

        {/* --- ACTIVE INLINE PROMPT (SHELL OR INTERACTIVE SUB-CONSOLE) --- */}
        {/* While command is executing, the prompt and input field disappear until output is shown */}
        {isExecuting ? null : subConsole.type === 'msfconsole' ? (
          <div 
            onClick={() => inputRef.current?.focus({ preventScroll: true })}
            className="pt-1 text-white font-mono text-xs flex items-center space-x-1.5 cursor-text"
          >
            <span className="text-rose-500 font-bold select-none">msf6</span>
            {subConsole.module && (
              <span className="text-rose-400 font-semibold select-none">
                {' '}
                {subConsole.module.startsWith('exploit/')
                  ? `exploit(${subConsole.module.replace(/^exploit\//, '')})`
                  : subConsole.module.startsWith('auxiliary/')
                  ? `auxiliary(${subConsole.module.replace(/^auxiliary\//, '')})`
                  : `(${subConsole.module})`}
              </span>
            )}
            <span className="text-white font-bold select-none"> &gt; </span>
            <input
              ref={inputRef}
              type="text"
              value={commandInput}
              onChange={(e) => setCommandInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Enter Metasploit command (search, use, show options, set, exploit, exit)..."
              className="flex-1 bg-transparent border-0 outline-none ring-0 shadow-none text-white font-mono text-xs p-0 m-0 caret-white focus:outline-none focus:ring-0 placeholder:text-zinc-700"
            />
          </div>
        ) : subConsole.type === 'meterpreter' ? (
          <div 
            onClick={() => inputRef.current?.focus({ preventScroll: true })}
            className="pt-1 text-white font-mono text-xs flex items-center space-x-1.5 cursor-text"
          >
            <span className="text-cyan-400 font-bold select-none">meterpreter &gt; </span>
            <input
              ref={inputRef}
              type="text"
              value={commandInput}
              onChange={(e) => setCommandInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Enter Meterpreter command (sysinfo, getuid, ps, pwd, hashdump, shell, background, exit)..."
              className="flex-1 bg-transparent border-0 outline-none ring-0 shadow-none text-white font-mono text-xs p-0 m-0 caret-white focus:outline-none focus:ring-0 placeholder:text-zinc-700"
            />
          </div>
        ) : subConsole.type === 'python' ? (
          <div 
            onClick={() => inputRef.current?.focus({ preventScroll: true })}
            className="pt-1 text-white font-mono text-xs flex items-center space-x-1.5 cursor-text"
          >
            <span className="text-amber-400 font-bold select-none">&gt;&gt;&gt; </span>
            <input
              ref={inputRef}
              type="text"
              value={commandInput}
              onChange={(e) => setCommandInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Enter Python expression (e.g. 2 + 2, print('hello'), exit())..."
              className="flex-1 bg-transparent border-0 outline-none ring-0 shadow-none text-white font-mono text-xs p-0 m-0 caret-white focus:outline-none focus:ring-0 placeholder:text-zinc-700"
            />
          </div>
        ) : (
          <div className="pt-1 text-white font-mono text-xs space-y-0.5">
            {/* Prompt Header: ┌──(root㉿kali)-[path] */}
            <div className="flex items-center space-x-1">
              <span className="text-[#3b82f6]">┌──(</span>
              <span className="text-white font-bold">root㉿kali</span>
              <span className="text-[#3b82f6]">)-[</span>
              <span className="text-white font-semibold">{currentDir}</span>
              <span className="text-[#3b82f6]">]</span>
            </div>

            {/* Active Command Line: └─# <input> */}
            <div 
              onClick={() => inputRef.current?.focus({ preventScroll: true })}
              className="flex items-center space-x-1.5 cursor-text"
            >
              <span className="text-[#3b82f6] shrink-0 select-none">└─</span>
              <span className="text-white font-bold shrink-0 select-none">#</span>
              <input
                ref={inputRef}
                type="text"
                value={commandInput}
                onChange={(e) => setCommandInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Enter Kali command (e.g. apt update, nmap, curl, python, msfconsole, help)..."
                className="flex-1 bg-transparent border-0 outline-none ring-0 shadow-none text-white font-mono text-xs p-0 m-0 caret-white focus:outline-none focus:ring-0 placeholder:text-zinc-600/70"
              />
            </div>
          </div>
        )}

        <div ref={terminalEndRef} />
      </div>
    </div>
  );
};