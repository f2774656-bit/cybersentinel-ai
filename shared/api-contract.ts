export type Role = 'ADMIN' | 'ANALYST' | 'VIEWER';
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';
export type ScanStatus = 'QUEUED' | 'VALIDATING' | 'RUNNING' | 'ANALYZING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface ApiError {
  code: string;
  message: string;
  request_id: string;
}

export interface SecurityScoreData {
  overall_score: number | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}
