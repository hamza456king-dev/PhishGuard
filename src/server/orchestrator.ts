import {
  analyzeEmailSample,
  analyzeFileBuffer,
  analyzeMessageContent,
  analyzeUrlStructure,
  synthesizeSecurityVerdict,
} from '../engine/analyzers';
import { MANDATORY_ACCEPTANCE_TESTS } from '../engine/acceptanceCases';
import { AnalysisCase, PhishGuardReport, SampleType } from '../types/phishguard';
import { enrichReportWithGemini } from './geminiEngine';
import { analyzeImageSampleServer } from './imageForensics';
import { probeUrlIsolated } from './networkProber';
import { runThreatIntelLookups } from './threatIntelManager';

export interface AnalysisRequestInput {
  sampleType: SampleType;
  sampleName?: string;
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
  consentExternal?: boolean;
  useGeminiEnrichment?: boolean;
}

/**
 * Central 12-stage Security Analysis Orchestrator.
 */
export async function executeFullSecurityAnalysis(input: AnalysisRequestInput): Promise<PhishGuardReport> {
  const consentExternal = Boolean(input.consentExternal);
  const useGemini = input.useGeminiEnrichment !== false;

  // --- 1. URL SCANNER PIPELINE ---
  if (input.sampleType === 'URL') {
    const rawUrl = (input.url || '').trim();
    const struct = analyzeUrlStructure(rawUrl);

    if (!struct.valid || !struct.normalizedUrl) {
      return synthesizeSecurityVerdict({
        sampleType: 'URL',
        sampleName: rawUrl || 'Invalid URL',
        indicators: struct.indicators,
        threatTypes: struct.threatTypes,
        linkStatus: 'UNKNOWN',
        targetUrl: rawUrl,
        checksPerformed: ['URL Structural Validation'],
        checksNotPerformed: ['DNS Resolution', 'Isolated HTTP Probe'],
        limitations: ['بنية الرابط المدخل غير صالحة.'],
      });
    }

    const probe = await probeUrlIsolated(struct.normalizedUrl, {
      simulateRedirectTo: input.simulateRedirectTo,
      simulateUnreachable: input.simulateUnreachable,
    });

    const intel = await runThreatIntelLookups({
      domain: struct.details.domain,
      url: struct.normalizedUrl,
      ipAddress: probe.ipAddress,
      consentExternal,
    });

    const mergedDetails = {
      ...struct.details,
      redirect_chain: probe.redirectChain,
      dns_records: probe.dnsRecords,
      ip_address: probe.ipAddress || struct.details.ip_address,
      tls_status: probe.tlsStatus,
      http_status: probe.httpStatus,
      page_title: probe.pageTitle,
      has_login_form: probe.hasLoginForm,
      has_otp_field: probe.hasOtpField,
      has_payment_form: probe.hasPaymentForm,
    };

    const allIndicators = [...struct.indicators, ...probe.additionalIndicators];
    const allThreats = Array.from(new Set([...struct.threatTypes, ...probe.additionalThreats]));

    const baseReport = synthesizeSecurityVerdict({
      sampleType: 'URL',
      sampleName: struct.normalizedUrl,
      indicators: allIndicators,
      threatTypes: allThreats,
      linkStatus: probe.linkStatus,
      targetUrl: struct.normalizedUrl,
      finalUrl: probe.finalUrl,
      domain: mergedDetails.domain,
      domainDetails: mergedDetails,
      reputationResults: intel.results,
      checksPerformed: [
        'URL Structural & Lexical Analyzer',
        'IDN Homoglyph & Punycode Inspector',
        'Brand Spoofing Detector',
        'SSRF & DNS Rebinding Guard',
        'Isolated HTTP/TLS Reachability Prober',
        ...intel.checksPerformed,
      ],
      checksNotPerformed: intel.checksNotPerformed,
      limitations: probe.probeLimitations,
    });

    return useGemini ? enrichReportWithGemini(baseReport, rawUrl) : baseReport;
  }

  // --- 2. MESSAGE SCANNER PIPELINE ---
  if (input.sampleType === 'MESSAGE') {
    const msgText = (input.message || '').trim();
    const msgRes = analyzeMessageContent(msgText);
    const primaryUrl = msgRes.extractedUrls[0] || null;
    const primaryUrlAnalysis = msgRes.urlAnalyses[0] || null;

    const intel = await runThreatIntelLookups({
      domain: primaryUrlAnalysis?.details.domain || null,
      url: primaryUrl,
      consentExternal,
    });

    const baseReport = synthesizeSecurityVerdict({
      sampleType: 'MESSAGE',
      sampleName: input.sampleName || `رسالة نصية (${msgText.slice(0, 42)}...)`,
      indicators: msgRes.indicators,
      threatTypes: msgRes.threatTypes,
      linkStatus: primaryUrl ? 'UNKNOWN' : 'NOT_APPLICABLE',
      targetUrl: primaryUrl,
      domain: primaryUrlAnalysis?.details.domain || null,
      domainDetails: primaryUrlAnalysis?.details || null,
      reputationResults: intel.results,
      checksPerformed: [
        'SMS & Social Media Message Analyzer',
        'Social Engineering & Urgency Detector',
        'OTP & Financial Lure Inspector',
        ...(primaryUrl ? ['Embedded URL Structural Analyzer'] : []),
        ...intel.checksPerformed,
      ],
      checksNotPerformed: intel.checksNotPerformed,
      limitations: primaryUrl ? ['تم فحص بنية الرابط المضمّن ساكناً دون فتحه تلقائياً.'] : [],
    });

    return useGemini ? enrichReportWithGemini(baseReport, msgText) : baseReport;
  }

  // --- 3. EMAIL SCANNER PIPELINE ---
  if (input.sampleType === 'EMAIL') {
    const rawEmail = (input.emailRaw || '').trim();
    const emailRes = analyzeEmailSample(rawEmail);
    const primaryUrl = emailRes.extractedUrls[0] || null;
    const primaryUrlStruct = primaryUrl ? analyzeUrlStructure(primaryUrl) : null;

    const intel = await runThreatIntelLookups({
      domain: emailRes.auth.from_address?.split('@')[1] || primaryUrlStruct?.details.domain || null,
      url: primaryUrl,
      consentExternal,
    });

    const checksPerformed = [
      'Email Header & Authentication Forensics (SPF/DKIM/DMARC)',
      'Sender Alignment Inspector (From / Reply-To / Return-Path)',
      'HTML Anchor Deception Detector',
      'Email Body Social Engineering Analyzer',
      ...intel.checksPerformed,
    ];

    const checksNotPerformed = [...intel.checksNotPerformed];
    if (emailRes.auth.spf === 'UNKNOWN' && emailRes.auth.dmarc === 'UNKNOWN') {
      checksNotPerformed.push('التحقق من SPF/DKIM/DMARC (لم تتوفر ترويسات Authentication-Results في النص المدخل)');
    }

    const baseReport = synthesizeSecurityVerdict({
      sampleType: 'EMAIL',
      sampleName: emailRes.auth.subject || input.sampleName || 'رسالة بريد إلكتروني',
      indicators: emailRes.indicators,
      threatTypes: emailRes.threatTypes,
      linkStatus: primaryUrl ? 'UNKNOWN' : 'NOT_APPLICABLE',
      targetUrl: primaryUrl,
      domain: primaryUrlStruct?.details.domain || emailRes.auth.from_address?.split('@')[1] || null,
      domainDetails: primaryUrlStruct?.details || null,
      emailAuth: emailRes.auth,
      reputationResults: intel.results,
      checksPerformed,
      checksNotPerformed,
      limitations: [
        'نجاح مصادقة SPF/DKIM/DMARC (إن وجد) يثبت هوية نطاق الإرسال التقني فقط ولا يضمن سلامة محتوى الرسالة.',
      ],
    });

    return useGemini ? enrichReportWithGemini(baseReport, rawEmail) : baseReport;
  }

  // --- 4. FILE SCANNER PIPELINE ---
  if (input.sampleType === 'FILE') {
    const fileName = input.fileName || input.sampleName || 'uploaded_sample.bin';
    const buffer = input.fileContentBase64
      ? Buffer.from(input.fileContentBase64, 'base64')
      : Buffer.from('');

    const fileRes = analyzeFileBuffer(fileName, buffer, input.fileMimeType);
    const primaryExtractedUrl = fileRes.fileAnalysis.extracted_urls?.[0] || null;
    const urlStruct = primaryExtractedUrl ? analyzeUrlStructure(primaryExtractedUrl) : null;

    const intel = await runThreatIntelLookups({
      sha256: fileRes.fileAnalysis.sha256,
      domain: urlStruct?.details.domain || null,
      url: primaryExtractedUrl,
      consentExternal,
    });

    const checksPerformed = [
      'Cryptographic Hash Calculation (SHA-256 / SHA-1 / MD5)',
      'Magic Bytes Binary Signature Identification',
      'Extension Mismatch & Double-Extension Detector',
      ...(fileRes.isSupported ? ['Static Code, Document & Archive Inspector'] : []),
      ...intel.checksPerformed,
    ];

    const checksNotPerformed = [
      ...(!fileRes.isSupported ? ['Deep Static Content Analysis (Unsupported Format)'] : []),
      'Dynamic Malware Sandbox Execution (غير مُهيأ — بيئة تحليل ساكنة آمنة)',
      ...intel.checksNotPerformed,
    ];

    const baseReport = synthesizeSecurityVerdict({
      sampleType: 'FILE',
      sampleName: fileName,
      indicators: fileRes.indicators,
      threatTypes: fileRes.threatTypes,
      linkStatus: primaryExtractedUrl ? 'UNKNOWN' : 'NOT_APPLICABLE',
      targetUrl: primaryExtractedUrl,
      domain: urlStruct?.details.domain || null,
      domainDetails: urlStruct?.details || null,
      fileAnalysis: fileRes.fileAnalysis,
      reputationResults: intel.results,
      checksPerformed,
      checksNotPerformed,
      limitations: fileRes.unsupportedReason
        ? [fileRes.unsupportedReason]
        : ['تم إجراء التحليل الساكن (Static Analysis) دون تشغيل الملف في بيئة الإنتاج.'],
      isUnsupportedFile: !fileRes.isSupported,
      unsupportedReason: fileRes.unsupportedReason,
    });

    return useGemini && fileRes.isSupported
      ? enrichReportWithGemini(baseReport, buffer.subarray(0, 1024).toString('utf8'))
      : baseReport;
  }

  // --- 5. IMAGE & QR SCANNER PIPELINE ---
  const imgFileName = input.fileName || input.sampleName || 'image_sample.png';
  const imgBuffer = input.fileContentBase64 ? Buffer.from(input.fileContentBase64, 'base64') : undefined;

  const imgRes = await analyzeImageSampleServer({
    fileName: imgFileName,
    buffer: imgBuffer,
    clientQrDecoded: input.qrPayload,
    simulatedDescription: input.imageDescription,
  });

  const urlStruct = imgRes.extractedUrl ? analyzeUrlStructure(imgRes.extractedUrl) : null;
  const intel = await runThreatIntelLookups({
    domain: imgRes.domain,
    url: imgRes.extractedUrl,
    consentExternal,
  });

  const baseReport = synthesizeSecurityVerdict({
    sampleType: 'IMAGE',
    sampleName: imgFileName,
    indicators: imgRes.indicators,
    threatTypes: imgRes.threatTypes,
    linkStatus: imgRes.extractedUrl ? 'UNKNOWN' : 'NOT_APPLICABLE',
    targetUrl: imgRes.extractedUrl,
    domain: imgRes.domain,
    domainDetails: urlStruct?.details || null,
    imageAnalysis: imgRes.imageDetails,
    reputationResults: intel.results,
    checksPerformed: [...imgRes.checksPerformed, ...intel.checksPerformed],
    checksNotPerformed: [...imgRes.checksNotPerformed, ...intel.checksNotPerformed],
    limitations: [imgRes.imageDetails.steganography_note],
  });

  return useGemini
    ? enrichReportWithGemini(
        baseReport,
        `${imgRes.imageDetails.ocr_text || ''} ${imgRes.imageDetails.qr_decoded_payload || ''}`
      )
    : baseReport;
}

/**
 * Generates initial baseline reports by running actual deterministic analyses on a subset of test samples.
 */
export async function generateInitialBaselineReports(): Promise<PhishGuardReport[]> {
  const initialCases = [
    MANDATORY_ACCEPTANCE_TESTS[0], // SAFE URL
    MANDATORY_ACCEPTANCE_TESTS[1], // PHISHING Bank URL
    MANDATORY_ACCEPTANCE_TESTS[5], // PHISHING OTP SMS
    MANDATORY_ACCEPTANCE_TESTS[7], // PHISHING DMARC Fail Email
    MANDATORY_ACCEPTANCE_TESTS[10], // MALICIOUS ZIP Script
    MANDATORY_ACCEPTANCE_TESTS[12], // UNKNOWN Unsupported File
  ];

  const reports: PhishGuardReport[] = [];
  for (const tc of initialCases) {
    const r = await executeFullSecurityAnalysis({
      sampleType: tc.sampleType,
      sampleName: tc.titleAr,
      ...tc.payload,
      consentExternal: false,
      useGeminiEnrichment: false,
    });
    reports.push(r);
  }
  return reports;
}

/**
 * Unified Multi-Input Case Analysis Orchestrator.
 * Analyzes multiple distinct inputs (e.g. Email + File Attachment + Extracted URL + Screenshot)
 * under one consolidated case ID while keeping each sample's technical findings strictly separate.
 */
export interface MultiInputCaseRequest {
  caseName: string;
  inputs: AnalysisRequestInput[];
  consentExternal?: boolean;
  useGeminiEnrichment?: boolean;
}

export async function executeMultiInputCaseAnalysis(params: MultiInputCaseRequest): Promise<AnalysisCase> {
  const caseId = `CASE-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
  const createdAt = new Date().toISOString();
  const sampleReports: PhishGuardReport[] = [];

  for (const item of params.inputs) {
    const report = await executeFullSecurityAnalysis({
      ...item,
      consentExternal: params.consentExternal,
      useGeminiEnrichment: params.useGeminiEnrichment,
    });
    report.case_id = caseId;
    sampleReports.push(report);
  }

  // Determine consolidated case classification & severity based on highest-risk constituent sample
  const classPriority: Record<PhishGuardReport['classification'], number> = {
    MALICIOUS: 5,
    PHISHING: 4,
    SUSPICIOUS: 3,
    UNKNOWN: 2,
    SAFE: 1,
  };
  const sevPriority: Record<PhishGuardReport['severity'], number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFO: 1,
  };

  let overallClass: PhishGuardReport['classification'] = 'SAFE';
  let overallSev: PhishGuardReport['severity'] = 'INFO';
  let totalIndicators = 0;
  let confidenceSum = 0;
  const threatSet = new Set<string>();

  for (const r of sampleReports) {
    if (classPriority[r.classification] > classPriority[overallClass]) {
      overallClass = r.classification;
    }
    if (sevPriority[r.severity] > sevPriority[overallSev]) {
      overallSev = r.severity;
    }
    totalIndicators += r.indicators.length;
    confidenceSum += r.confidence;
    r.threat_types.forEach((t) => threatSet.add(t));
  }

  const overallConfidence =
    sampleReports.length > 0 ? Math.round(confidenceSum / sampleReports.length) : 0;

  const summaryText = `تم تحليل ${sampleReports.length} عينة مستقلة ضمن القضية "${params.caseName}". كل عينة تحتفظ بأدلتها الجنائية المستقلة، والتصنيف الإجمالي للقضية هو ${overallClass} بمستوى خطورة ${overallSev} بعد رصد ${totalIndicators} مؤشر تقني.`;

  return {
    case_id: caseId,
    case_name: params.caseName || `قضية تحليل مركبة (${sampleReports.length} عينات)`,
    created_at: createdAt,
    overall_classification: overallClass,
    overall_severity: overallSev,
    overall_confidence: overallConfidence,
    sample_count: sampleReports.length,
    total_indicators: totalIndicators,
    threat_types: Array.from(threatSet),
    executive_summary: summaryText,
    consolidated_summary: summaryText,
    final_verdict: `${overallClass} (الخطورة: ${overallSev} | عدد العينات: ${sampleReports.length}) — تقييم قضية متعددة المدخلات مع فصل كامل لأدلة كل عينة.`,
    samples: sampleReports,
  };
}


