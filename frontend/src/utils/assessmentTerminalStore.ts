import type { TerminalLogEntry, ScanJob, AuthorizedAsset } from '../types/api';

export interface KaliLogEntry {
  id: string;
  type: 'input' | 'output' | 'error' | 'success' | 'system' | 'banner';
  content: string;
  timestamp: string;
}

export interface AssessmentTerminalState {
  // Kali Terminal State
  kaliLogs: KaliLogEntry[];
  kaliActiveAssetId: string;
  kaliCustomPort: string;
  commandHistory: string[];
  stagedCommand?: string | null;

  // Red Team Live Scanner Terminal State
  showLiveTerminal: boolean;
  selectedTerminalAsset: AuthorizedAsset | null;
  inlineTerminalLogs: TerminalLogEntry[];
  latestScanJob: ScanJob | null;
  lastScannedAssetId: string | null;
}

const STORAGE_KEY = 'vulnsentinel_assessment_terminal_state';

// In-memory singleton store for cross-tab SPA navigation within the session.
// When the whole website page is refreshed (F5 / browser reload), this in-memory store
// cleanly resets so that the Kali Terminal and Red Team Scanner Terminal refresh freshly as requested.
let memoryStore: AssessmentTerminalState | null = null;

function getInitialState(): AssessmentTerminalState {
  return {
    kaliLogs: [],
    kaliActiveAssetId: 'personal',
    kaliCustomPort: '443',
    commandHistory: [],
    showLiveTerminal: false,
    selectedTerminalAsset: null,
    inlineTerminalLogs: [],
    latestScanJob: null,
    lastScannedAssetId: null,
  };
}

export function getAssessmentTerminalState(): AssessmentTerminalState {
  if (!memoryStore) {
    memoryStore = getInitialState();
  }
  return memoryStore;
}

export function setAssessmentTerminalState(partial: Partial<AssessmentTerminalState>): AssessmentTerminalState {
  if (!memoryStore) {
    memoryStore = getInitialState();
  }

  memoryStore = {
    ...memoryStore,
    ...partial,
  };

  return memoryStore;
}

export function saveKaliLogs(logs: KaliLogEntry[]): void {
  setAssessmentTerminalState({ kaliLogs: logs });
}

export function clearAssessmentTerminalState(): void {
  memoryStore = getInitialState();
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      window.sessionStorage.removeItem(STORAGE_KEY);
    }
  } catch {}
}

// Clean up any legacy sessionStorage data so page reload/refresh always starts with fresh terminals
if (typeof window !== 'undefined') {
  try {
    window.sessionStorage?.removeItem(STORAGE_KEY);
  } catch {}

  window.addEventListener('beforeunload', () => {
    try {
      window.sessionStorage?.removeItem(STORAGE_KEY);
    } catch {}
  });
}


