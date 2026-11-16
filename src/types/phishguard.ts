export type SampleType = 'URL' | 'MESSAGE' | 'EMAIL' | 'FILE' | 'IMAGE';

export type SecurityClassification =
  | 'SAFE'
  | 'SUSPICIOUS'
  | 'PHISHING'
  | 'MALICIOUS'
  | 'UNKNOWN';

export type SeverityLevel = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type LinkStatus =
  | 'WORKING'
  | 'REDIRECTED'
  | 'UNREACHABLE'
  | 'BLOCKED'
  | 'NOT_APPLICABLE'
  | 'UNKNOWN';

export type SpfStatus =
  | 'PASS'
  | 'FAIL'
  | 'SOFTFAIL'
  | 'NEUTRAL'
  | 'NONE'
  | 'UNKNOWN'
  | 'NOT_APPLICABLE';

export type DkimStatus =
  | 'PASS'
  | 'FAIL'
  | 'NONE'
  | 'UNKNOWN'
  | 'NOT_APPLICABLE';

export type DmarcStatus =
  | 'PASS'
  | 'FAIL'
  | 'NONE'
  | 'UNKNOWN'
  | 'NOT_APPLICABLE';

export interface TechnicalIndicator {
  name: string;
  evidence: string;
  source: string;
  severity: SeverityLevel;
  verified: boolean;
  category?: 'TOOL_RESULT' | 'HEURISTIC' | 'AI_OBSERVATION' | 'UNVERIFIED_ASSUMPTION';
}

export interface ReputationResult {
  provider: string;
  status: 'CONNECTED' | 'NOT_CONFIGURED' | 'ERROR' | 'COMPLETED';
  last_checked: string;
  verdict: string;
  details: string;
  freshness: string;
  error?: string | null;
}

export interface EmailAuthenticationResult {
  spf: SpfStatus;
  dkim: DkimStatus;
  dmarc: DmarcStatus;
  from_address?: string | null;
  from_display_name?: string | null;
  reply_to?: string | null;
  return_path?: string | null;
  subject?: string | null;
  sender_ip?: string | null;
  alignment_notes?: string[];
}

export interface FileAnalysisResult {
  sha256: string | null;
  sha1?: string | null;
  md5?: string | null;
  file_size?: number | null;
  extension?: string | null;
  declared_mime_type?: string | null;
  detected_mime_type: string | null;
  magic_bytes_hex?: string | null;
  extension_mismatch?: boolean;
  static_analysis: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNSUPPORTED' | 'NOT_RUN';
  antivirus: 'CLEAN' | 'DETECTED' | 'NOT_CONFIGURED' | 'NOT_RUN';
  sandbox: 'CLEAN' | 'MALICIOUS' | 'NOT_CONFIGURED' | 'NOT_RUN';
  archive_entries?: string[];
  extracted_urls?: string[];
}

export interface DomainAnalysisDetails {
  domain: string | null;
  subdomain: string | null;
  tld: string | null;
  protocol: string | null;
  port: string | null;
  path: string | null;
  query_params: string[];
  is_ip_host: boolean;
  has_userinfo: boolean;
  is_shortener: boolean;
  is_punycode: boolean;
  has_homoglyphs: boolean;
  homoglyph_details: string[];
  impersonated_brand: string | null;
  redirect_chain: string[];
  dns_records: string[];
  ip_address: string | null;
  tls_status: string;
  http_status: number | null;
  page_title: string | null;
  has_login_form: boolean;
  has_otp_field: boolean;
  has_payment_form: boolean;
}

export interface ImageAnalysisDetails {
  ocr_text: string | null;
  qr_decoded_payload: string | null;
  extracted_urls: string[];
  visual_brand_detected: string | null;
  exif_summary: string | null;
  dimensions: string | null;
  steganography_note: string;
}

export interface PhishGuardReport {
  analysis_id: string;
  analyzed_at: string;
  sample_type: SampleType;
  sample_name: string;
  classification: SecurityClassification;
  severity: SeverityLevel;
  confidence: number;
  link_status: LinkStatus;
  target_url: string | null;
  final_url: string | null;
  domain: string | null;
  threat_types: string[];
  indicators: TechnicalIndicator[];
  reputation_results: ReputationResult[];
  email_authentication: EmailAuthenticationResult;
  file_analysis: FileAnalysisResult;
  domain_details?: DomainAnalysisDetails | null;
  image_analysis?: ImageAnalysisDetails | null;
  content_analysis?: string;
  threat_explanation?: string;
  checks_performed: string[];
  checks_not_performed: string[];
  limitations: string[];
  user_recommendations: string[];
  executive_summary: string;
  final_verdict: string;
  markdown_report?: string;
  case_id?: string | null;
}

export interface AnalysisCase {
  case_id: string;
  case_name: string;
  created_at: string;
  overall_classification: SecurityClassification;
  overall_severity: SeverityLevel;
  overall_confidence: number;
  sample_count: number;
  total_indicators?: number;
  threat_types?: string[];
  executive_summary: string;
  consolidated_summary?: string;
  consolidated_recommendations?: string[];
  final_verdict?: string;
  samples: PhishGuardReport[];
}

export interface IocLookupResult {
  query: string;
  indicatorType: 'SHA256' | 'DOMAIN' | 'IP' | 'URL';
  queriedAt: string;
  classification: SecurityClassification;
  severity: SeverityLevel;
  confidence: number;
  summaryAr: string;
  structuralIndicators: TechnicalIndicator[];
  reputationResults: ReputationResult[];
  dnsRecords?: string[];
  ipAddress?: string | null;
  tlsStatus?: string;
  matchedHistory: Array<{
    analysis_id: string;
    analyzed_at: string;
    sample_type: SampleType;
    sample_name: string;
    classification: SecurityClassification;
    severity: SeverityLevel;
  }>;
}

export type PrimaryNavSection =
  | 'DASHBOARD'
  | 'ANALYSIS_CENTER'
  | 'THREAT_INTEL'
  | 'HISTORY_REPORTS'
  | 'MORE';

export type AnalysisMode = SampleType | 'MULTI_INPUT_CASE';

export type MoreSubSection =
  | 'INTEGRATIONS'
  | 'SYSTEM_HEALTH'
  | 'SETTINGS_PRIVACY'
  | 'USER_ACCESS'
  | 'AUDIT_LOGS'
  | 'DOCS_HELP'
  | 'DEV_DIAGNOSTICS';

export interface ThreatIntelProviderStatus {
  id: string;
  name: string;
  category: string;
  configured: boolean;
  status: 'ONLINE' | 'NOT_CONFIGURED' | 'DEGRADED';
  lastCheck: string | null;
  capabilities: string[];
  unavailableCapabilities: string[];
}

export interface AcceptanceTestCase {
  id: string;
  number: number;
  titleAr: string;
  titleEn: string;
  sampleType: SampleType;
  expectedClassification: SecurityClassification[];
  expectedLinkStatus?: LinkStatus[];
  descriptionAr: string;
  payload: {
    url?: string;
    simulateRedirectTo?: string;
    simulateUnreachable?: boolean;
    message?: string;
    emailRaw?: string;
    fileName?: string;
    fileMimeType?: string;
    fileContentBase64?: string;
    imageDescription?: string;
    qrPayload?: string;
  };
}
