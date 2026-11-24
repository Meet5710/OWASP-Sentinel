import React from 'react';
import { ProofOfConceptTab } from './ProofOfConceptTab';
import type { AuthorizedAsset, Finding, ScanJob } from '../types/api';

export interface ReportsTabProps {
  assets: AuthorizedAsset[];
  findings: Finding[];
  scans: ScanJob[];
  selectedTargetId?: string;
  onSelectTarget?: (targetId: string) => void;
  onRefreshData?: () => Promise<void>;
}

/**
 * Backward compatibility alias: ReportsTab now maps directly to ProofOfConceptTab.
 */
export const ReportsTab: React.FC<ReportsTabProps> = (props) => {
  return <ProofOfConceptTab {...props} />;
};

export default ReportsTab;
