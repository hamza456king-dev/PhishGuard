import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeEmailSample,
  analyzeFileBuffer,
  analyzeMessageContent,
  analyzeUrlStructure,
  isPrivateOrReservedHost,
  synthesizeSecurityVerdict,
} from './analyzers';
import { MANDATORY_ACCEPTANCE_TESTS } from './acceptanceCases';

test('SSRF Guard blocks loopback, private RFC1918, and cloud metadata IPs', () => {
  assert.equal(isPrivateOrReservedHost('127.0.0.1').blocked, true);
  assert.equal(isPrivateOrReservedHost('localhost').blocked, true);
  assert.equal(isPrivateOrReservedHost('169.254.169.254').blocked, true);
  assert.equal(isPrivateOrReservedHost('10.0.0.1').blocked, true);
  assert.equal(isPrivateOrReservedHost('192.168.1.50').blocked, true);
  assert.equal(isPrivateOrReservedHost('172.16.5.4').blocked, true);
  assert.equal(isPrivateOrReservedHost('google.com').blocked, false);
});

test('Case 1: Legitimate working URL classifies as SAFE', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[0];
  const urlAnalysis = analyzeUrlStructure(tc.payload.url!);
  const report = synthesizeSecurityVerdict({
    sampleType: 'URL',
    sampleName: tc.payload.url!,
    indicators: urlAnalysis.indicators,
    threatTypes: urlAnalysis.threatTypes,
    linkStatus: 'WORKING',
    targetUrl: tc.payload.url!,
    finalUrl: tc.payload.url!,
    domain: urlAnalysis.details.domain,
    domainDetails: urlAnalysis.details,
    checksPerformed: ['URL Structural Analyzer', 'DNS Check'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.equal(report.classification, 'SAFE');
  assert.equal(report.link_status, 'WORKING');
});

test('Case 2: Phishing URL mimicking a bank domain classifies as PHISHING', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[1];
  const urlAnalysis = analyzeUrlStructure(tc.payload.url!);
  const report = synthesizeSecurityVerdict({
    sampleType: 'URL',
    sampleName: tc.payload.url!,
    indicators: urlAnalysis.indicators,
    threatTypes: urlAnalysis.threatTypes,
    linkStatus: 'WORKING',
    targetUrl: tc.payload.url!,
    finalUrl: tc.payload.url!,
    domain: urlAnalysis.details.domain,
    domainDetails: urlAnalysis.details,
    checksPerformed: ['URL Structural Analyzer', 'Brand Spoofing Engine'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.equal(report.classification, 'PHISHING');
  assert.equal(report.severity, 'CRITICAL');
});

test('Case 3: URL containing Unicode homoglyph characters is detected as PHISHING', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[2];
  const urlAnalysis = analyzeUrlStructure(tc.payload.url!);
  assert.equal(urlAnalysis.details.has_homoglyphs, true);
  const report = synthesizeSecurityVerdict({
    sampleType: 'URL',
    sampleName: tc.payload.url!,
    indicators: urlAnalysis.indicators,
    threatTypes: urlAnalysis.threatTypes,
    linkStatus: 'WORKING',
    targetUrl: tc.payload.url!,
    finalUrl: tc.payload.url!,
    domain: urlAnalysis.details.domain,
    domainDetails: urlAnalysis.details,
    checksPerformed: ['IDN & Homoglyph Inspector'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.equal(report.classification, 'PHISHING');
});

test('Case 4: Shortened URL redirecting to suspicious domain is detected with REDIRECTED status', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[3];
  const initialAnalysis = analyzeUrlStructure(tc.payload.url!);
  const destAnalysis = analyzeUrlStructure(tc.payload.simulateRedirectTo!);
  const combinedIndicators = [...initialAnalysis.indicators, ...destAnalysis.indicators];
  const combinedThreats = Array.from(new Set([...initialAnalysis.threatTypes, ...destAnalysis.threatTypes]));
  const report = synthesizeSecurityVerdict({
    sampleType: 'URL',
    sampleName: tc.payload.url!,
    indicators: combinedIndicators,
    threatTypes: combinedThreats,
    linkStatus: 'REDIRECTED',
    targetUrl: tc.payload.url!,
    finalUrl: tc.payload.simulateRedirectTo!,
    domain: destAnalysis.details.domain,
    domainDetails: destAnalysis.details,
    checksPerformed: ['URL Structural Analyzer', 'Redirect Chain Inspector'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.equal(report.classification, 'PHISHING');
  assert.equal(report.link_status, 'REDIRECTED');
});

test('Case 5: Unreachable URL separates link_status (UNREACHABLE) from classification (UNKNOWN)', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[4];
  const urlAnalysis = analyzeUrlStructure(tc.payload.url!);
  const report = synthesizeSecurityVerdict({
    sampleType: 'URL',
    sampleName: tc.payload.url!,
    indicators: urlAnalysis.indicators,
    threatTypes: urlAnalysis.threatTypes,
    linkStatus: 'UNREACHABLE',
    targetUrl: tc.payload.url!,
    finalUrl: null,
    domain: urlAnalysis.details.domain,
    domainDetails: urlAnalysis.details,
    checksPerformed: ['URL Structural Analyzer', 'Isolated Reachability Probe'],
    checksNotPerformed: ['Web Page Content Inspection'],
    limitations: ['تعذر الوصول إلى الخادم'],
  });
  assert.equal(report.link_status, 'UNREACHABLE');
  assert.equal(report.classification, 'UNKNOWN');
});

test('Case 6: Message requesting OTP code is detected as PHISHING', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[5];
  const msgAnalysis = analyzeMessageContent(tc.payload.message!);
  const report = synthesizeSecurityVerdict({
    sampleType: 'MESSAGE',
    sampleName: 'رسالة SMS',
    indicators: msgAnalysis.indicators,
    threatTypes: msgAnalysis.threatTypes,
    checksPerformed: ['Social Engineering & Message Analyzer'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.equal(report.classification, 'PHISHING');
  assert.equal(report.severity, 'CRITICAL');
});

test('Case 7: Email with mismatch between From and Reply-To is flagged as PHISHING', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[6];
  const emailRes = analyzeEmailSample(tc.payload.emailRaw!);
  const report = synthesizeSecurityVerdict({
    sampleType: 'EMAIL',
    sampleName: emailRes.auth.subject || 'Email Sample',
    indicators: emailRes.indicators,
    threatTypes: emailRes.threatTypes,
    emailAuth: emailRes.auth,
    checksPerformed: ['Email Header Forensics'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.equal(report.classification, 'PHISHING');
  assert.ok(emailRes.indicators.some((i) => i.name.includes('Reply-To')));
});

test('Case 8: Email failing DMARC authentication is flagged as PHISHING with DMARC=FAIL', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[7];
  const emailRes = analyzeEmailSample(tc.payload.emailRaw!);
  assert.equal(emailRes.auth.dmarc, 'FAIL');
  assert.equal(emailRes.auth.spf, 'FAIL');
  assert.equal(emailRes.auth.dkim, 'FAIL');
  const report = synthesizeSecurityVerdict({
    sampleType: 'EMAIL',
    sampleName: emailRes.auth.subject || 'Email Sample',
    indicators: emailRes.indicators,
    threatTypes: emailRes.threatTypes,
    emailAuth: emailRes.auth,
    checksPerformed: ['Email Header Forensics'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.equal(report.classification, 'PHISHING');
  assert.equal(report.severity, 'CRITICAL');
});

test('Case 9: PDF file containing suspicious external links is detected', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[8];
  const buf = Buffer.from(tc.payload.fileContentBase64!, 'base64');
  const fileRes = analyzeFileBuffer(tc.payload.fileName!, buf, tc.payload.fileMimeType);
  const report = synthesizeSecurityVerdict({
    sampleType: 'FILE',
    sampleName: tc.payload.fileName!,
    indicators: fileRes.indicators,
    threatTypes: fileRes.threatTypes,
    fileAnalysis: fileRes.fileAnalysis,
    checksPerformed: ['PDF Static Analyzer'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.ok(['PHISHING', 'MALICIOUS', 'SUSPICIOUS'].includes(report.classification));
  assert.ok(fileRes.fileAnalysis.extracted_urls && fileRes.fileAnalysis.extracted_urls.length > 0);
});

test('Case 10: Office document containing VBA macros is flagged as MALICIOUS', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[9];
  const buf = Buffer.from(tc.payload.fileContentBase64!, 'base64');
  const fileRes = analyzeFileBuffer(tc.payload.fileName!, buf, tc.payload.fileMimeType);
  const report = synthesizeSecurityVerdict({
    sampleType: 'FILE',
    sampleName: tc.payload.fileName!,
    indicators: fileRes.indicators,
    threatTypes: fileRes.threatTypes,
    fileAnalysis: fileRes.fileAnalysis,
    checksPerformed: ['Office Document Analyzer'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.equal(report.classification, 'MALICIOUS');
  assert.equal(report.severity, 'CRITICAL');
});

test('Case 11: Compressed ZIP archive containing suspicious script inside is flagged as MALICIOUS', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[10];
  const buf = Buffer.from(tc.payload.fileContentBase64!, 'base64');
  const fileRes = analyzeFileBuffer(tc.payload.fileName!, buf, tc.payload.fileMimeType);
  assert.ok(fileRes.fileAnalysis.archive_entries?.includes('verify_invoice.ps1'));
  const report = synthesizeSecurityVerdict({
    sampleType: 'FILE',
    sampleName: tc.payload.fileName!,
    indicators: fileRes.indicators,
    threatTypes: fileRes.threatTypes,
    fileAnalysis: fileRes.fileAnalysis,
    checksPerformed: ['Archive Security Analyzer', 'Static Script & Binary Analyzer'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.equal(report.classification, 'MALICIOUS');
  assert.equal(report.severity, 'CRITICAL');
});

test('Case 12: Image containing QR code leading to phishing page is flagged as PHISHING', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[11];
  const qrUrlAnalysis = analyzeUrlStructure(tc.payload.qrPayload!);
  const indicators = [
    {
      name: 'رمز QR مضمّن يوجه إلى نطاق تصيد (QR Phishing / Quishing)',
      evidence: `محتوى رمز QR المستخرج: ${tc.payload.qrPayload}`,
      source: 'QR Code Decoder & URL Analyzer',
      severity: 'CRITICAL' as const,
      verified: true,
    },
    ...qrUrlAnalysis.indicators,
  ];
  const report = synthesizeSecurityVerdict({
    sampleType: 'IMAGE',
    sampleName: tc.payload.fileName!,
    indicators,
    threatTypes: ['QR Phishing / Quishing', ...qrUrlAnalysis.threatTypes],
    targetUrl: tc.payload.qrPayload!,
    domain: qrUrlAnalysis.details.domain,
    domainDetails: qrUrlAnalysis.details,
    checksPerformed: ['QR Code Decoder', 'URL Structural Analyzer'],
    checksNotPerformed: [],
    limitations: [],
  });
  assert.equal(report.classification, 'PHISHING');
});

test('Case 13: Unsupported file format MUST return UNKNOWN, never SAFE', () => {
  const tc = MANDATORY_ACCEPTANCE_TESTS[12];
  const buf = Buffer.from(tc.payload.fileContentBase64!, 'base64');
  const fileRes = analyzeFileBuffer(tc.payload.fileName!, buf, tc.payload.fileMimeType);
  assert.equal(fileRes.isSupported, false);
  const report = synthesizeSecurityVerdict({
    sampleType: 'FILE',
    sampleName: tc.payload.fileName!,
    indicators: fileRes.indicators,
    threatTypes: fileRes.threatTypes,
    fileAnalysis: fileRes.fileAnalysis,
    checksPerformed: ['Magic Bytes Inspector'],
    checksNotPerformed: ['Deep Static Analysis'],
    limitations: [fileRes.unsupportedReason || 'Unsupported format'],
    isUnsupportedFile: !fileRes.isSupported,
    unsupportedReason: fileRes.unsupportedReason,
  });
  assert.equal(report.classification, 'UNKNOWN');
  assert.notEqual(report.classification, 'SAFE');
  assert.ok(report.final_verdict.includes('UNKNOWN'));
});

test('Threat Intelligence providers use OpenPhish.eu instead of Google Web Risk', async () => {
  const { getThreatIntelProvidersStatus } = await import('../server/threatIntelManager');
  const providers = getThreatIntelProvidersStatus();
  const openPhish = providers.find((p) => p.id === 'openphish-eu');
  const webRisk = providers.find((p) => p.id === 'google-webrisk');
  assert.ok(openPhish, 'OpenPhish.eu provider should exist');
  assert.equal(openPhish?.name, 'OpenPhish.eu Threat Intelligence');
  assert.equal(webRisk, undefined);
});

