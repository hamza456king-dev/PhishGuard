import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  FileCode2,
  FileText,
  Globe,
  HelpCircle,
  Lock,
  Mail,
  Printer,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
} from 'lucide-react';
import { PhishGuardReport, SecurityClassification, SeverityLevel } from '../types/phishguard';

interface ReportViewProps {
  report: PhishGuardReport;
  lang: 'ar' | 'en';
  onReanalyze?: (report: PhishGuardReport) => void;
}

export function getClassificationMeta(classification: SecurityClassification, lang: 'ar' | 'en') {
  switch (classification) {
    case 'SAFE':
      return {
        label: lang === 'ar' ? 'SAFE — آمن (لا توجد مؤشرات خطر)' : 'SAFE — No Threat Indicators',
        shortLabel: lang === 'ar' ? 'SAFE (آمن)' : 'SAFE',
        colorClass: 'text-emerald-700 dark:text-emerald-400',
        bgClass: 'bg-emerald-500/10 border-emerald-500/30',
        Icon: ShieldCheck,
      };
    case 'SUSPICIOUS':
      return {
        label: lang === 'ar' ? 'SUSPICIOUS — مشبوه (يستدعي الحذر)' : 'SUSPICIOUS — Caution Advised',
        shortLabel: lang === 'ar' ? 'SUSPICIOUS (مشبوه)' : 'SUSPICIOUS',
        colorClass: 'text-amber-700 dark:text-amber-400',
        bgClass: 'bg-amber-500/10 border-amber-500/30',
        Icon: ShieldAlert,
      };
    case 'PHISHING':
      return {
        label: lang === 'ar' ? 'PHISHING / FRAUD — تصيد احتيالي أو خداع' : 'PHISHING / FRAUD — Confirmed Lure',
        shortLabel: lang === 'ar' ? 'PHISHING (تصيد)' : 'PHISHING',
        colorClass: 'text-rose-700 dark:text-rose-400',
        bgClass: 'bg-rose-500/10 border-rose-500/30',
        Icon: ShieldX,
      };
    case 'MALICIOUS':
      return {
        label: lang === 'ar' ? 'MALICIOUS — خبيث (تهديد برمجي ضار)' : 'MALICIOUS — Harmful Payload',
        shortLabel: lang === 'ar' ? 'MALICIOUS (خبيث)' : 'MALICIOUS',
        colorClass: 'text-red-700 dark:text-red-400',
        bgClass: 'bg-red-500/10 border-red-500/30',
        Icon: AlertTriangle,
      };
    default:
      return {
        label: lang === 'ar' ? 'UNKNOWN — غير معروف / أدلة غير كافية' : 'UNKNOWN — Insufficient Evidence / Unsupported',
        shortLabel: lang === 'ar' ? 'UNKNOWN (غير معروف)' : 'UNKNOWN',
        colorClass: 'text-slate-700 dark:text-slate-300',
        bgClass: 'bg-slate-500/10 border-slate-500/30',
        Icon: ShieldQuestion,
      };
  }
}

export function getSeverityColor(severity: SeverityLevel): string {
  switch (severity) {
    case 'CRITICAL':
      return 'text-red-600 dark:text-red-400 font-semibold';
    case 'HIGH':
      return 'text-rose-600 dark:text-rose-400 font-semibold';
    case 'MEDIUM':
      return 'text-amber-600 dark:text-amber-400 font-medium';
    case 'LOW':
      return 'text-sky-600 dark:text-sky-400';
    default:
      return 'text-slate-600 dark:text-slate-400';
  }
}

export function getLinkStatusLabel(status: PhishGuardReport['link_status'], lang: 'ar' | 'en'): string {
  if (lang === 'en') return status;
  switch (status) {
    case 'WORKING':
      return 'WORKING — يعمل ويستجيب';
    case 'REDIRECTED':
      return 'REDIRECTED — يعمل مع إعادة توجيه';
    case 'UNREACHABLE':
      return 'UNREACHABLE — غير قابل للوصول / لا يستجيب';
    case 'BLOCKED':
      return 'BLOCKED — محجوب أو يتطلب مصادقة';
    case 'NOT_APPLICABLE':
      return 'NOT_APPLICABLE — لا ينطبق';
    default:
      return 'UNKNOWN — تعذر التحقق';
  }
}

export const ReportView: React.FC<ReportViewProps> = ({ report, lang, onReanalyze }) => {
  const [activeTab, setActiveTab] = useState<'structured' | 'markdown' | 'json'>('structured');
  const [copied, setCopied] = useState(false);

  const meta = getClassificationMeta(report.classification, lang);
  const StatusIcon = meta.Icon;

  // Build strict Section 16 JSON schema object
  const strictJsonOutput = {
    analysis_id: report.analysis_id,
    analyzed_at: report.analyzed_at,
    sample_type: report.sample_type,
    sample_name: report.sample_name,
    classification: report.classification,
    severity: report.severity,
    confidence: report.confidence,
    link_status: report.link_status,
    target_url: report.target_url,
    final_url: report.final_url,
    domain: report.domain,
    threat_types: report.threat_types,
    indicators: report.indicators.map((i) => ({
      name: i.name,
      evidence: i.evidence,
      source: i.source,
      severity: i.severity,
      verified: i.verified,
    })),
    reputation_results: report.reputation_results,
    email_authentication: {
      spf: report.email_authentication.spf,
      dkim: report.email_authentication.dkim,
      dmarc: report.email_authentication.dmarc,
    },
    file_analysis: {
      sha256: report.file_analysis.sha256,
      detected_mime_type: report.file_analysis.detected_mime_type,
      static_analysis: report.file_analysis.static_analysis,
      antivirus: report.file_analysis.antivirus,
      sandbox: report.file_analysis.sandbox,
    },
    checks_performed: report.checks_performed,
    checks_not_performed: report.checks_not_performed,
    limitations: report.limitations,
    user_recommendations: report.user_recommendations,
    executive_summary: report.executive_summary,
    final_verdict: report.final_verdict,
  };

  const handleDownloadJson = () => {
    const blob = new Blob([JSON.stringify(strictJsonOutput, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.analysis_id}-phishguard.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadMarkdown = () => {
    const content = report.markdown_report || '';
    const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.analysis_id}-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(strictJsonOutput, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="space-y-6" data-testid="forensic-report-view">
      {/* Top Report Header Banner */}
      <div className={`p-6 rounded-xl border ${meta.bgClass} transition-colors`}>
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400 font-mono tabular-nums">
              <span>PHISHGUARD SECURITY ANALYSIS REPORT</span>
              <span aria-hidden="true">·</span>
              <span>{report.analysis_id}</span>
              <span aria-hidden="true">·</span>
              <span>{new Date(report.analyzed_at).toLocaleString(lang === 'ar' ? 'ar-SA' : 'en-US')}</span>
            </div>

            <div className="flex items-center gap-3">
              <StatusIcon className={`w-7 h-7 shrink-0 ${meta.colorClass}`} />
              <h2 className={`text-xl sm:text-2xl font-bold tracking-tight ${meta.colorClass}`}>
                {meta.label}
              </h2>
            </div>

            <p className="text-sm text-slate-800 dark:text-slate-200 max-w-4xl leading-relaxed">
              {report.executive_summary}
            </p>
          </div>

          {/* Action Toolbar */}
          <div className="flex flex-wrap items-center gap-2 shrink-0 no-print">
            {onReanalyze && (
              <button
                type="button"
                onClick={() => onReanalyze(report)}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>{lang === 'ar' ? 'إعادة الفحص' : 'Re-analyze'}</span>
              </button>
            )}
            <button
              type="button"
              onClick={handleDownloadJson}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{lang === 'ar' ? 'تصدير JSON' : 'Export JSON'}</span>
            </button>
            <button
              type="button"
              onClick={handleDownloadMarkdown}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>{lang === 'ar' ? 'تصدير التقرير النصي' : 'Export Report MD'}</span>
            </button>
            <button
              type="button"
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-sky-600 hover:bg-sky-500 text-white transition-colors whitespace-nowrap shrink-0"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>{lang === 'ar' ? 'طباعة / PDF' : 'Print / PDF'}</span>
            </button>
          </div>
        </div>

        {/* Key Forensic Metrics Bar (Decoupled Classification, Severity, Confidence, Link Status) */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6 pt-5 border-t border-slate-200/60 dark:border-slate-800/80">
          <div>
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? 'نوع العينة ومسمّاها' : 'Sample Type & Name'}
            </div>
            <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100 truncate" title={report.sample_name}>
              {report.sample_type} · {report.sample_name}
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? 'مستوى الخطورة (Severity)' : 'Severity Level'}
            </div>
            <div className={`mt-1 text-sm font-mono tabular-nums ${getSeverityColor(report.severity)}`}>
              {report.severity}
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? 'درجة الثقة بالأدلة (Confidence)' : 'Evidence Confidence'}
            </div>
            <div className="mt-1 text-sm font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
              {report.confidence} / 100
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? 'حالة عمل الرابط (مستقلة عن الأمان)' : 'Link Reachability (Independent)'}
            </div>
            <div className="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
              {getLinkStatusLabel(report.link_status, lang)}
            </div>
          </div>
        </div>
      </div>

      {/* View Mode Switcher */}
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3 no-print">
        <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800">
          <button
            type="button"
            onClick={() => setActiveTab('structured')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'structured'
                ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            {lang === 'ar' ? 'التقرير الجنائي المفصل' : 'Structured Forensic View'}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('markdown')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'markdown'
                ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            {lang === 'ar' ? 'التقرير الرسمي (11 قسماً)' : '11-Section Formal Report'}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('json')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'json'
                ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            {lang === 'ar' ? 'مخرجات JSON القياسية' : 'Strict JSON Output'}
          </button>
        </div>
      </div>

      {activeTab === 'json' && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
              PHISHGUARD_STRICT_JSON_SCHEMA (Section 16)
            </span>
            <button
              type="button"
              onClick={handleCopyJson}
              className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>{copied ? (lang === 'ar' ? 'تم النسخ' : 'Copied') : lang === 'ar' ? 'نسخ JSON' : 'Copy JSON'}</span>
            </button>
          </div>
          <pre
            dir="ltr"
            className="text-xs font-mono text-slate-800 dark:text-slate-200 bg-slate-50 dark:bg-slate-950 p-4 rounded-lg overflow-x-auto leading-relaxed"
          >
            {JSON.stringify(strictJsonOutput, null, 2)}
          </pre>
        </div>
      )}

      {activeTab === 'markdown' && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
          <pre className="whitespace-pre-wrap text-sm font-sans text-slate-800 dark:text-slate-200 leading-relaxed">
            {report.markdown_report}
          </pre>
        </div>
      )}

      {activeTab === 'structured' && (
        <div className="space-y-6">
          {/* Section: Technical Indicators & Evidence */}
          <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mb-4">
              {lang === 'ar'
                ? `01. المؤشرات التقنية والأدلة الجنائية (${report.indicators.length})`
                : `01. Technical Indicators & Forensic Evidence (${report.indicators.length})`}
            </h3>

            {report.indicators.length === 0 ? (
              <div className="flex items-center gap-2 text-sm text-emerald-700 dark:text-emerald-400 py-3">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>
                  {lang === 'ar'
                    ? 'لم يتم رصد مؤشرات خطر تقنية أو سلوكية في نطاق الفحوص المنفذة.'
                    : 'No technical or behavioral threat indicators detected within executed checks.'}
                </span>
              </div>
            ) : (
              <div className="divide-y divide-slate-200 dark:divide-slate-800">
                {report.indicators.map((ind, idx) => (
                  <div key={idx} className="py-3.5 first:pt-0 last:pb-0">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                        {ind.name}
                      </span>
                      <div className="flex items-center gap-2 text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
                        <span className={getSeverityColor(ind.severity)}>{ind.severity}</span>
                        <span aria-hidden="true">·</span>
                        <span>{ind.source}</span>
                        <span aria-hidden="true">·</span>
                        <span>
                          {ind.verified
                            ? lang === 'ar'
                              ? 'دليل أداة محقق (Verified)'
                            : 'Verified Tool Evidence'
                            : lang === 'ar'
                            ? 'ملاحظة تحليلية (Observation)'
                            : 'Analytical Observation'}
                        </span>
                      </div>
                    </div>
                    <p className="mt-1.5 text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
                      {ind.evidence}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Conditional Section: URL & Domain Infrastructure Details */}
          {(report.domain_details || report.target_url) && (
            <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Globe className="w-4 h-4 text-sky-500" />
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  {lang === 'ar' ? '02. تحليل بنية النطاق والروابط والشبكة' : '02. Domain, URL & Network Forensics'}
                </h3>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-sm">
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200/70 dark:border-slate-800">
                  <div className="text-xs text-slate-500 dark:text-slate-400">الرابط المستهدف (Target URL)</div>
                  <div dir="ltr" className="mt-1 font-mono text-xs break-all text-slate-900 dark:text-slate-100">
                    {report.target_url || 'غير متاح'}
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200/70 dark:border-slate-800">
                  <div className="text-xs text-slate-500 dark:text-slate-400">الوجهة النهائية (Final URL)</div>
                  <div dir="ltr" className="mt-1 font-mono text-xs break-all text-slate-900 dark:text-slate-100">
                    {report.final_url || 'غير متاح'}
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200/70 dark:border-slate-800">
                  <div className="text-xs text-slate-500 dark:text-slate-400">النطاق الأساسي والفرعي (Domain / Subdomain)</div>
                  <div dir="ltr" className="mt-1 font-mono text-xs text-slate-900 dark:text-slate-100">
                    Domain: {report.domain || 'N/A'} | Sub: {report.domain_details?.subdomain || 'None'}
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200/70 dark:border-slate-800">
                  <div className="text-xs text-slate-500 dark:text-slate-400">فحص الأحرف المتشابهة (Punycode / Homoglyph)</div>
                  <div className="mt-1 text-xs font-medium text-slate-900 dark:text-slate-100">
                    {report.domain_details?.has_homoglyphs
                      ? `مكتشف: ${report.domain_details.homoglyph_details.join('، ') || 'Punycode (xn--)'}`
                      : 'سليم (لا يوجد تمويه Unicode أو Punycode)'}
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200/70 dark:border-slate-800">
                  <div className="text-xs text-slate-500 dark:text-slate-400">عنوان IP وسجلات DNS</div>
                  <div dir="ltr" className="mt-1 font-mono text-xs text-slate-900 dark:text-slate-100">
                    IP: {report.domain_details?.ip_address || 'غير متاح'}
                    {report.domain_details?.dns_records && report.domain_details.dns_records.length > 0 && (
                      <div className="text-slate-500 mt-0.5">{report.domain_details.dns_records.join(' | ')}</div>
                    )}
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200/70 dark:border-slate-800">
                  <div className="text-xs text-slate-500 dark:text-slate-400">حالة شهادة TLS/SSL</div>
                  <div className="mt-1 text-xs text-slate-900 dark:text-slate-100">
                    {report.domain_details?.tls_status || 'غير متاح'}
                  </div>
                </div>
              </div>

              {report.domain_details?.redirect_chain && report.domain_details.redirect_chain.length > 1 && (
                <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800">
                  <div className="text-xs font-semibold text-slate-600 dark:text-slate-400 mb-2">
                    {lang === 'ar' ? 'سلسلة إعادة التوجيه (Redirect Chain):' : 'Redirect Chain:'}
                  </div>
                  <div dir="ltr" className="space-y-1 font-mono text-xs text-slate-800 dark:text-slate-200">
                    {report.domain_details.redirect_chain.map((hop, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <span className="text-sky-500">Hop #{i + 1}:</span>
                        <span className="break-all">{hop}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}

          {/* Conditional Section: Email Authentication Details */}
          {report.sample_type === 'EMAIL' && (
            <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Mail className="w-4 h-4 text-sky-500" />
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  {lang === 'ar'
                    ? '03. مصادقة البريد الإلكتروني وترويسات الإرسال (SPF / DKIM / DMARC)'
                    : '03. Email Authentication & Header Alignment'}
                </h3>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-xs text-slate-500">SPF (Sender Policy Framework)</div>
                  <div className="mt-1 font-mono text-sm font-bold text-slate-900 dark:text-slate-100">
                    {report.email_authentication.spf}
                  </div>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-xs text-slate-500">DKIM (DomainKeys Identified Mail)</div>
                  <div className="mt-1 font-mono text-sm font-bold text-slate-900 dark:text-slate-100">
                    {report.email_authentication.dkim}
                  </div>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-xs text-slate-500">DMARC (Domain-based Auth)</div>
                  <div className="mt-1 font-mono text-sm font-bold text-slate-900 dark:text-slate-100">
                    {report.email_authentication.dmarc}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block">From:</span>
                  <span className="text-slate-900 dark:text-slate-100 break-all">
                    {report.email_authentication.from_address || 'غير متوفر'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block">Reply-To:</span>
                  <span className="text-slate-900 dark:text-slate-100 break-all">
                    {report.email_authentication.reply_to || 'غير محدد (يطابق From)'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block">Return-Path:</span>
                  <span className="text-slate-900 dark:text-slate-100 break-all">
                    {report.email_authentication.return_path || 'غير متوفر'}
                  </span>
                </div>
              </div>
            </section>
          )}

          {/* Conditional Section: File & Archive Analysis */}
          {report.sample_type === 'FILE' && (
            <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
              <div className="flex items-center gap-2 mb-4">
                <FileCode2 className="w-4 h-4 text-sky-500" />
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  {lang === 'ar'
                    ? '03. التحليل الجنائي للملف والتوقيع الثنائي (Static File & Magic Bytes Analysis)'
                    : '03. File Cryptographic Hashes & Static Forensics'}
                </h3>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-slate-500">بصمة SHA-256</div>
                  <div dir="ltr" className="mt-1 break-all text-slate-900 dark:text-slate-100">
                    {report.file_analysis.sha256 || 'غير متاح'}
                  </div>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-slate-500">التوقيع الثنائي الفعلي (Detected MIME & Magic Bytes)</div>
                  <div dir="ltr" className="mt-1 text-slate-900 dark:text-slate-100">
                    MIME: {report.file_analysis.detected_mime_type} | Hex: {report.file_analysis.magic_bytes_hex || 'N/A'}
                  </div>
                </div>
              </div>

              {report.file_analysis.archive_entries && report.file_analysis.archive_entries.length > 0 && (
                <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800">
                  <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
                    {lang === 'ar'
                      ? `محتويات الأرشيف المفحوصة دون تشغيل (${report.file_analysis.archive_entries.length} ملف):`
                      : `Archive Entries Inspected Safely (${report.file_analysis.archive_entries.length}):`}
                  </div>
                  <div dir="ltr" className="flex flex-wrap gap-2 font-mono text-xs text-slate-700 dark:text-slate-300">
                    {report.file_analysis.archive_entries.map((entry, idx) => (
                      <span key={idx} className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-800">
                        {entry}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}

          {/* Conditional Section: Image & QR Analysis */}
          {report.image_analysis && (
            <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mb-4">
                {lang === 'ar'
                  ? '03. نتائج فحص الصورة ورموز QR والتعرف الضوئي (OCR & Quishing Forensics)'
                  : '03. Image OCR, QR Decoder & Visual Forensics'}
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-xs text-slate-500">محتوى رمز QR المفكوك (Decoded QR Payload)</div>
                  <div dir="ltr" className="mt-1 font-mono text-xs break-all text-slate-900 dark:text-slate-100">
                    {report.image_analysis.qr_decoded_payload || 'لم يتم رصد رمز QR في الصورة'}
                  </div>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-xs text-slate-500">النصوص المستخرجة (OCR Text)</div>
                  <div className="mt-1 text-xs text-slate-900 dark:text-slate-100">
                    {report.image_analysis.ocr_text || 'لا توجد نصوص مستخرجة'}
                  </div>
                </div>
              </div>
              <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
                {report.image_analysis.steganography_note}
              </p>
            </section>
          )}

          {/* Section: Threat Intelligence Sources & Verification Scope */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mb-3">
                {lang === 'ar' ? '04. الفحوص المنفذة مقابل غير المنفذة والقيود' : '04. Checks Executed vs Not Executed'}
              </h3>
              <div className="space-y-3 text-xs">
                <div>
                  <div className="font-semibold text-emerald-700 dark:text-emerald-400 mb-1">
                    {lang === 'ar' ? 'الفحوص التي تم تنفيذها فعلياً:' : 'Checks Performed:'}
                  </div>
                  <ul className="space-y-1 text-slate-700 dark:text-slate-300">
                    {report.checks_performed.map((c, i) => (
                      <li key={i}>• {c}</li>
                    ))}
                  </ul>
                </div>

                {report.checks_not_performed.length > 0 && (
                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
                    <div className="font-semibold text-amber-700 dark:text-amber-400 mb-1">
                      {lang === 'ar' ? 'الفحوص التي لم تُنفذ (بشفافية كاملة):' : 'Checks Not Performed:'}
                    </div>
                    <ul className="space-y-1 text-slate-600 dark:text-slate-400">
                      {report.checks_not_performed.map((c, i) => (
                        <li key={i}>• {c}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {report.limitations.length > 0 && (
                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
                    <div className="font-semibold text-slate-700 dark:text-slate-300 mb-1">
                      {lang === 'ar' ? 'القيود والملاحظات المنهجية:' : 'Methodological Limitations:'}
                    </div>
                    <ul className="space-y-1 text-slate-600 dark:text-slate-400">
                      {report.limitations.map((lim, i) => (
                        <li key={i}>• {lim}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </section>

            {/* Section: Actionable User Recommendations & Final Verdict */}
            <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Lock className="w-4 h-4 text-sky-500" />
                  <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                    {lang === 'ar' ? '05. التوصيات الأمنية المباشرة للمستخدم' : '05. Actionable Security Recommendations'}
                  </h3>
                </div>
                <ul className="space-y-2 text-sm text-slate-700 dark:text-slate-300">
                  {report.user_recommendations.map((rec, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-sky-500 font-bold">•</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800">
                <div className="text-xs font-semibold text-slate-500 dark:text-slate-400">
                  {lang === 'ar' ? 'الحكم النهائي (Final Verdict):' : 'Final Verdict:'}
                </div>
                <p className={`mt-1 text-sm font-bold ${meta.colorClass}`}>
                  {report.final_verdict}
                </p>
              </div>
            </section>
          </div>
        </div>
      )}
    </div>
  );
};
