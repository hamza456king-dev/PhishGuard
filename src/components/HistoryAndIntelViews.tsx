import React, { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  FileText,
  FolderKanban,
  Globe,
  Loader2,
  Printer,
  RefreshCw,
  Search,
  ShieldAlert,
  Trash2,
  XCircle,
} from 'lucide-react';
import {
  AnalysisCase,
  IocLookupResult,
  PhishGuardReport,
  SampleType,
  SecurityClassification,
  SeverityLevel,
  ThreatIntelProviderStatus,
} from '../types/phishguard';
import { ReportView, getClassificationMeta, getSeverityColor } from './ReportView';

interface HistoryAndReportsViewProps {
  lang: 'ar' | 'en';
  scans: PhishGuardReport[];
  cases: AnalysisCase[];
  initialSearchQuery?: string;
  initialSelectedReport?: PhishGuardReport | null;
  onDeleteScan: (analysisId: string) => void;
  onReanalyzeSample: (report: PhishGuardReport) => void;
  onOpenCaseInWorkspace?: (analysisCase: AnalysisCase) => void;
}

export const HistoryAndReportsView: React.FC<HistoryAndReportsViewProps> = ({
  lang,
  scans,
  cases,
  initialSearchQuery = '',
  initialSelectedReport,
  onDeleteScan,
  onReanalyzeSample,
  onOpenCaseInWorkspace,
}) => {
  const [subTab, setSubTab] = useState<'ALL' | 'CASES' | 'SAMPLES' | 'REPORTS'>('ALL');
  const [searchQuery, setSearchQuery] = useState(initialSearchQuery);
  const [filterClass, setFilterClass] = useState<'ALL' | SecurityClassification>('ALL');
  const [filterSeverity, setFilterSeverity] = useState<'ALL' | SeverityLevel>('ALL');
  const [filterType, setFilterType] = useState<'ALL' | SampleType>('ALL');
  const [dateRange, setDateRange] = useState<'ALL' | 'TODAY' | '7D' | '30D'>('ALL');

  const [selectedReport, setSelectedReport] = useState<PhishGuardReport | null>(
    initialSelectedReport || scans[0] || null
  );
  const [selectedCase, setSelectedCase] = useState<AnalysisCase | null>(cases[0] || null);

  useEffect(() => {
    if (initialSearchQuery !== undefined) {
      setSearchQuery(initialSearchQuery);
    }
  }, [initialSearchQuery]);

  useEffect(() => {
    if (initialSelectedReport) {
      setSelectedReport(initialSelectedReport);
    }
  }, [initialSelectedReport]);

  const matchesDateRange = (isoDate: string) => {
    if (dateRange === 'ALL') return true;
    const ts = new Date(isoDate).getTime();
    if (Number.isNaN(ts)) return true;
    const diffMs = Date.now() - ts;
    if (dateRange === 'TODAY') return diffMs <= 24 * 60 * 60 * 1000;
    if (dateRange === '7D') return diffMs <= 7 * 24 * 60 * 60 * 1000;
    if (dateRange === '30D') return diffMs <= 30 * 24 * 60 * 60 * 1000;
    return true;
  };

  const filteredScans = scans.filter((s) => {
    if (filterClass !== 'ALL' && s.classification !== filterClass) return false;
    if (filterSeverity !== 'ALL' && s.severity !== filterSeverity) return false;
    if (filterType !== 'ALL' && s.sample_type !== filterType) return false;
    if (!matchesDateRange(s.analyzed_at)) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      const hay = [
        s.analysis_id,
        s.sample_name,
        s.domain || '',
        s.target_url || '',
        s.file_analysis?.sha256 || '',
        s.executive_summary,
      ]
        .join(' ')
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const filteredCases = cases.filter((c) => {
    if (filterClass !== 'ALL' && c.overall_classification !== filterClass) return false;
    if (filterSeverity !== 'ALL' && c.overall_severity !== filterSeverity) return false;
    if (!matchesDateRange(c.created_at)) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      const hay = [
        c.case_id,
        c.case_name,
        c.consolidated_summary,
        ...c.samples.map((s) => `${s.sample_name} ${s.domain || ''} ${s.file_analysis?.sha256 || ''}`),
      ]
        .join(' ')
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const exportAllFilteredJson = () => {
    const blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), cases: filteredCases, scans: filteredScans }, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-forensic-export-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-5">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white">
              {lang === 'ar'
                ? 'السجل والتقارير الجنائية الموحدة (History & Reports)'
                : 'Unified Forensic History & Reports'}
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              {lang === 'ar'
                ? 'ابحث بواسطة الرابط أو النطاق أو اسم الملف أو بصمة SHA-256، واستعرض القضايا متعددة المدخلات والعينات الفردية والتقارير القابلة للتصدير (PDF / JSON).'
                : 'Search by URL, domain, filename, or SHA-256 hash, and inspect unified cases, individual samples, and exportable forensic reports.'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={exportAllFilteredJson}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{lang === 'ar' ? 'تصدير السجل (JSON)' : 'Export JSON'}</span>
            </button>
            <button
              type="button"
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-lg bg-sky-600 hover:bg-sky-500 text-white"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>{lang === 'ar' ? 'طباعة / تصدير التقرير (PDF)' : 'Print / Export PDF'}</span>
            </button>
          </div>
        </div>

        {/* 4 Internal Sub-Tabs required by Section 3.4 */}
        <div className="flex flex-wrap gap-2 mb-5 pb-4 border-b border-slate-200 dark:border-slate-800" role="tablist">
          {[
            { id: 'ALL', labelAr: `جميع التحليلات (${filteredScans.length + filteredCases.length})`, labelEn: `All Analyses (${filteredScans.length + filteredCases.length})` },
            { id: 'CASES', labelAr: `القضايا متعددة المدخلات (${filteredCases.length})`, labelEn: `Cases (${filteredCases.length})` },
            { id: 'SAMPLES', labelAr: `العينات الفردية (${filteredScans.length})`, labelEn: `Individual Samples (${filteredScans.length})` },
            { id: 'REPORTS', labelAr: 'التقارير الجنائية والتصدير', labelEn: 'Reports & Export' },
          ].map((t) => {
            const active = subTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setSubTab(t.id as typeof subTab)}
                className={`px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors ${
                  active
                    ? 'bg-sky-600 text-white'
                    : 'bg-slate-100 dark:bg-slate-950 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800 hover:border-slate-300'
                }`}
              >
                {lang === 'ar' ? t.labelAr : t.labelEn}
              </button>
            );
          })}
        </div>

        {/* Search & 4 Filter Controls (Sample Type, Classification, Severity, Date Range) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 mb-5">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute top-2.5 start-3 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={
                lang === 'ar'
                  ? 'بحث بـ URL أو النطاق أو الملف أو SHA-256...'
                  : 'Search URL, domain, filename, SHA-256...'
              }
              aria-label={lang === 'ar' ? 'بحث في السجل والتقارير' : 'Search history and reports'}
              className="w-full ps-9 pe-3 py-2 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100"
            />
          </div>

          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value as 'ALL' | SampleType)}
            aria-label={lang === 'ar' ? 'تصفية حسب نوع العينة' : 'Filter by sample type'}
            className="px-3 py-2 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100"
          >
            <option value="ALL">{lang === 'ar' ? 'جميع أنواع العينات' : 'All Sample Types'}</option>
            <option value="URL">URL</option>
            <option value="MESSAGE">MESSAGE</option>
            <option value="EMAIL">EMAIL</option>
            <option value="FILE">FILE</option>
            <option value="IMAGE">IMAGE</option>
          </select>

          <select
            value={filterClass}
            onChange={(e) => setFilterClass(e.target.value as 'ALL' | SecurityClassification)}
            aria-label={lang === 'ar' ? 'تصفية حسب التصنيف' : 'Filter by classification'}
            className="px-3 py-2 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100"
          >
            <option value="ALL">{lang === 'ar' ? 'جميع التصنيفات الأمنية' : 'All Classifications'}</option>
            <option value="SAFE">SAFE (آمن)</option>
            <option value="SUSPICIOUS">SUSPICIOUS (مشبوه)</option>
            <option value="PHISHING">PHISHING (تصيد احتيالي)</option>
            <option value="MALICIOUS">MALICIOUS (خبيث)</option>
            <option value="UNKNOWN">UNKNOWN (غير معروف)</option>
          </select>

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value as 'ALL' | SeverityLevel)}
            aria-label={lang === 'ar' ? 'تصفية حسب الخطورة' : 'Filter by severity'}
            className="px-3 py-2 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100"
          >
            <option value="ALL">{lang === 'ar' ? 'جميع مستويات الخطورة' : 'All Severities'}</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFO">INFO</option>
          </select>

          <select
            value={dateRange}
            onChange={(e) => setDateRange(e.target.value as typeof dateRange)}
            aria-label={lang === 'ar' ? 'تصفية حسب النطاق الزمني' : 'Filter by date range'}
            className="px-3 py-2 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100"
          >
            <option value="ALL">{lang === 'ar' ? 'جميع الأوقات (All Dates)' : 'All Dates'}</option>
            <option value="TODAY">{lang === 'ar' ? 'اليوم (Last 24h)' : 'Last 24 Hours'}</option>
            <option value="7D">{lang === 'ar' ? 'آخر 7 أيام' : 'Last 7 Days'}</option>
            <option value="30D">{lang === 'ar' ? 'آخر 30 يوماً' : 'Last 30 Days'}</option>
          </select>
        </div>

        {/* Multi-Input Cases Section (shown in ALL and CASES sub-tabs) */}
        {(subTab === 'ALL' || subTab === 'CASES') && (
          <div className="mb-6">
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 mb-3 flex items-center gap-2">
              <FolderKanban className="w-4 h-4 text-sky-500" />
              <span>
                {lang === 'ar'
                  ? `سجل القضايا الجنائية متعددة المدخلات (${filteredCases.length})`
                  : `Multi-Input Investigation Cases (${filteredCases.length})`}
              </span>
            </h2>

            {filteredCases.length === 0 ? (
              <div className="p-4 rounded-lg border border-dashed border-slate-200 dark:border-slate-800 text-xs text-slate-500 text-center">
                {lang === 'ar' ? 'لا توجد قضايا متعددة المدخلات مطابقة.' : 'No matching multi-input cases.'}
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {filteredCases.map((c) => (
                  <div
                    key={c.case_id}
                    className={`p-4 rounded-xl border transition-colors ${
                      selectedCase?.case_id === c.case_id
                        ? 'border-sky-500 bg-sky-500/5'
                        : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className="font-mono font-bold text-sky-600 dark:text-sky-400">
                        {c.case_id} • {c.sample_count} {lang === 'ar' ? 'عينات' : 'samples'}
                      </span>
                      <span className="font-mono font-bold text-rose-600 dark:text-rose-400">
                        {c.overall_classification} ({c.overall_severity})
                      </span>
                    </div>
                    <div className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-1">
                      {c.case_name}
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 line-clamp-2">
                      {c.consolidated_summary}
                    </p>
                    <div className="mt-3 pt-2.5 border-t border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap gap-1.5">
                        {c.samples.map((s) => (
                          <button
                            key={s.analysis_id}
                            type="button"
                            onClick={() => {
                              setSelectedCase(c);
                              setSelectedReport(s);
                            }}
                            className="px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-sky-500"
                          >
                            {s.sample_type}: {s.classification}
                          </button>
                        ))}
                      </div>
                      {onOpenCaseInWorkspace && (
                        <button
                          type="button"
                          onClick={() => onOpenCaseInWorkspace(c)}
                          className="text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline"
                        >
                          {lang === 'ar' ? 'فتح في مركز التحليل' : 'Open in Analysis Center'}
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Individual Samples Table (shown in ALL, SAMPLES, and REPORTS sub-tabs) */}
        {subTab !== 'CASES' && (
          <div className="overflow-x-auto">
            <table className="w-full text-start border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'المعرّف' : 'ID'}</th>
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'التاريخ' : 'Timestamp'}</th>
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'النوع' : 'Type'}</th>
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'العينة / SHA-256' : 'Sample / SHA-256'}</th>
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'التصنيف' : 'Classification'}</th>
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'الخطورة' : 'Severity'}</th>
                  <th className="py-2.5 px-3 text-end font-medium">{lang === 'ar' ? 'إجراءات' : 'Actions'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {filteredScans.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-xs text-slate-500">
                      {lang === 'ar' ? 'لا توجد تقارير مطابقة لمعايير البحث الحالية.' : 'No matching scan reports found.'}
                    </td>
                  </tr>
                ) : (
                  filteredScans.map((s) => {
                    const meta = getClassificationMeta(s.classification, lang);
                    const isSelected = selectedReport?.analysis_id === s.analysis_id;
                    return (
                      <tr
                        key={s.analysis_id}
                        className={`transition-colors ${
                          isSelected
                            ? 'bg-sky-500/10'
                            : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                        }`}
                      >
                        <td className="py-3 px-3 font-mono text-xs text-slate-600 dark:text-slate-400">
                          {s.analysis_id}
                        </td>
                        <td className="py-3 px-3 font-mono tabular-nums text-xs text-slate-500">
                          {new Date(s.analyzed_at).toLocaleTimeString(lang === 'ar' ? 'ar-SA' : 'en-US')}
                        </td>
                        <td className="py-3 px-3 font-mono text-xs text-slate-700 dark:text-slate-300">
                          {s.sample_type}
                        </td>
                        <td className="py-3 px-3 text-xs">
                          <div className="font-semibold text-slate-900 dark:text-slate-100 max-w-xs truncate">
                            {s.sample_name}
                          </div>
                          {s.file_analysis?.sha256 && (
                            <div dir="ltr" className="font-mono text-[11px] text-slate-500 truncate max-w-xs">
                              SHA256: {s.file_analysis.sha256}
                            </div>
                          )}
                        </td>
                        <td className={`py-3 px-3 text-xs font-bold ${meta.colorClass}`}>
                          {meta.shortLabel}
                        </td>
                        <td className={`py-3 px-3 font-mono text-xs ${getSeverityColor(s.severity)}`}>
                          {s.severity}
                        </td>
                        <td className="py-3 px-3 text-end">
                          <div className="inline-flex items-center gap-3">
                            <button
                              type="button"
                              onClick={() => setSelectedReport(s)}
                              className="inline-flex items-center gap-1 text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap"
                            >
                              <FileText className="w-3.5 h-3.5" />
                              <span>{lang === 'ar' ? 'التقرير' : 'Report'}</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => onReanalyzeSample(s)}
                              title={lang === 'ar' ? 'إعادة فحص العينة' : 'Reanalyze sample'}
                              className="inline-flex items-center gap-1 text-xs font-semibold text-slate-600 dark:text-slate-300 hover:text-sky-500"
                            >
                              <RefreshCw className="w-3.5 h-3.5" />
                              <span className="hidden sm:inline">{lang === 'ar' ? 'إعادة فحص' : 'Reanalyze'}</span>
                            </button>
                            <button
                              type="button"
                              aria-label={`Delete ${s.analysis_id}`}
                              onClick={() => {
                                onDeleteScan(s.analysis_id);
                                if (selectedReport?.analysis_id === s.analysis_id) {
                                  setSelectedReport(null);
                                }
                              }}
                              className="text-slate-400 hover:text-red-500 transition-colors"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Full Forensic Report Viewer */}
      {selectedReport && (
        <ReportView
          report={selectedReport}
          lang={lang}
          onReanalyze={() => onReanalyzeSample(selectedReport)}
        />
      )}
    </div>
  );
};

interface ThreatIntelViewProps {
  lang: 'ar' | 'en';
  providers: ThreatIntelProviderStatus[];
  scans: PhishGuardReport[];
  consentExternal: boolean;
  onOpenIntegrationsInMore: () => void;
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({
  lang,
  providers,
  scans,
  consentExternal,
  onOpenIntegrationsInMore,
}) => {
  const [iocInput, setIocInput] = useState('xn--pple-43d.com');
  const [isLookingUp, setIsLookingUp] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [lookupResult, setLookupResult] = useState<IocLookupResult | null>(null);

  const sampleSha256 =
    scans.find((s) => s.file_analysis?.sha256)?.file_analysis.sha256 ||
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const executeIocQuery = async (targetQuery: string) => {
    const trimmed = targetQuery.trim();
    if (!trimmed) return;
    setIsLookingUp(true);
    setLookupError(null);
    try {
      const res = await fetch('/api/ioc-lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: trimmed, consentExternal }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'فشل استعلام مؤشر الاختراق.');
      }
      setLookupResult(data as IocLookupResult);
    } catch (err) {
      setLookupError(err instanceof Error ? err.message : 'حدث خطأ أثناء فحص المؤشر.');
    } finally {
      setIsLookingUp(false);
    }
  };

  useEffect(() => {
    executeIocQuery('xn--pple-43d.com');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-6">
      {/* Interactive IOC Lookup Workspace (Section 3.3) */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-5">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white">
              {lang === 'ar'
                ? 'استخبارات التهديدات وفحص مؤشرات الاختراق (Threat Intelligence & IOC Lookup)'
                : 'Threat Intelligence & Indicator of Compromise (IOC) Lookup'}
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              {lang === 'ar'
                ? 'ابحث عن أي مؤشر اختراق (رابط URL، اسم نطاق Domain، عنوان IP، أو بصمة ملف SHA-256) للتحقق من السمعة وسجلات DNS/TLS والتطابقات الجنائية المسجلة مع توثيق المصدر ووقت الاستعلام.'
                : 'Query any URL, Domain, IP address, or SHA-256 file hash against threat intelligence sources, DNS/TLS forensics, and local scan history.'}
            </p>
          </div>

          <button
            type="button"
            onClick={onOpenIntegrationsInMore}
            className="px-3.5 py-2 text-xs font-semibold rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:border-sky-500 shrink-0"
          >
            {lang === 'ar' ? 'إدارة تكاملات المزودين (المزيد ← التكاملات)' : 'Manage Providers (More → Integrations)'}
          </button>
        </div>

        {/* IOC Search Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            executeIocQuery(iocInput);
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Globe className="w-4 h-4 text-slate-400 absolute top-3 start-3.5 pointer-events-none" />
            <input
              type="text"
              dir="ltr"
              value={iocInput}
              onChange={(e) => setIocInput(e.target.value)}
              placeholder="domain.com | https://... | 198.51.100.42 | SHA-256 hash"
              aria-label="IOC Lookup Query"
              className="w-full ps-10 pe-4 py-2.5 text-sm font-mono rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
            />
          </div>
          <button
            type="submit"
            disabled={isLookingUp}
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 text-sm font-semibold rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white transition-colors shrink-0"
          >
            {isLookingUp ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>{lang === 'ar' ? 'فحص مؤشر الاختراق (IOC Lookup)' : 'Query IOC'}</span>
          </button>
        </form>

        {/* Quick Preset IOC Chips */}
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-500 font-semibold">
            {lang === 'ar' ? 'مؤشرات اختبار سريعة:' : 'Quick IOC Examples:'}
          </span>
          {[
            { label: 'Punycode Homograph (xn--pple-43d.com)', val: 'xn--pple-43d.com' },
            { label: 'Brand Spoof Domain (alrajh1-bank-verify-login.com)', val: 'alrajh1-bank-verify-login.com' },
            { label: 'Recorded File SHA-256', val: sampleSha256 },
            { label: 'Public Domain (google.com)', val: 'google.com' },
          ].map((chip) => (
            <button
              key={chip.label}
              type="button"
              onClick={() => {
                setIocInput(chip.val);
                executeIocQuery(chip.val);
              }}
              className="px-2.5 py-1 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-950 text-slate-700 dark:text-slate-300 hover:border-sky-500/50 font-mono text-[11px]"
            >
              {chip.label}
            </button>
          ))}
        </div>

        {lookupError && (
          <div className="mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{lookupError}</span>
          </div>
        )}

        {/* IOC Lookup Result Card */}
        {lookupResult && (
          <div className="mt-6 pt-6 border-t border-slate-200 dark:border-slate-800 space-y-5">
            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 flex flex-wrap items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-sky-500/15 text-sky-600 dark:text-sky-400">
                    {lookupResult.indicatorType}
                  </span>
                  <span className="font-mono text-sm font-bold text-slate-900 dark:text-white break-all" dir="ltr">
                    {lookupResult.query}
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300 mt-1.5">
                  {lookupResult.summaryAr}
                </p>
                <div className="text-[11px] font-mono text-slate-500 mt-1">
                  {lang === 'ar' ? 'وقت الاستعلام:' : 'Queried At:'} {lookupResult.queriedAt}
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="text-end">
                  <div className={`text-sm font-bold ${getClassificationMeta(lookupResult.classification, lang).colorClass}`}>
                    {lookupResult.classification} ({lookupResult.severity})
                  </div>
                  <div className="text-xs font-mono text-slate-500">
                    Confidence: {lookupResult.confidence}%
                  </div>
                </div>
              </div>
            </div>

            {/* Infrastructure & Reputation Sources */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3">
                  {lang === 'ar'
                    ? 'نتائج المصادر واستخبارات التهديدات (Source Attribution & Timestamps)'
                    : 'Threat Intelligence Source Results & Timestamps'}
                </h3>
                <div className="space-y-2.5">
                  {lookupResult.reputationResults.map((rep, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-xs"
                    >
                      <div className="flex items-center justify-between font-semibold">
                        <span className="text-slate-900 dark:text-slate-100">{rep.provider}</span>
                        <span className="font-mono text-[11px] text-sky-600 dark:text-sky-400">
                          {rep.verdict} ({rep.status})
                        </span>
                      </div>
                      <div className="text-slate-600 dark:text-slate-400 mt-1">{rep.details}</div>
                      <div className="text-[11px] font-mono text-slate-500 mt-1">
                        {lang === 'ar' ? 'آخر تحديث:' : 'Checked:'} {rep.last_checked} • {rep.freshness}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                  {lang === 'ar'
                    ? 'المؤشرات البنيوية والتطابقات في السجل المحلي'
                    : 'Structural Indicators & Local Forensic Matches'}
                </h3>

                {lookupResult.dnsRecords && lookupResult.dnsRecords.length > 0 && (
                  <div className="p-2.5 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs font-mono">
                    <div>DNS: {lookupResult.dnsRecords.join(' | ')}</div>
                    {lookupResult.tlsStatus && <div className="mt-1">TLS: {lookupResult.tlsStatus}</div>}
                  </div>
                )}

                {lookupResult.structuralIndicators.length === 0 ? (
                  <div className="text-xs text-slate-500">
                    {lang === 'ar'
                      ? 'لم تظهر مؤشرات خداع بنيوية مباشرة في هذا المؤشر.'
                      : 'No direct structural deception indicators detected.'}
                  </div>
                ) : (
                  <div className="space-y-2">
                    {lookupResult.structuralIndicators.map((ind, i) => (
                      <div
                        key={i}
                        className="p-2.5 rounded-lg border border-amber-500/30 bg-amber-500/5 text-xs"
                      >
                        <div className="font-bold text-slate-900 dark:text-slate-100">
                          {ind.name} ({ind.severity})
                        </div>
                        <div className="text-slate-600 dark:text-slate-300 mt-0.5">{ind.evidence}</div>
                        <div className="text-[11px] font-mono text-slate-500 mt-0.5">المصدر: {ind.source}</div>
                      </div>
                    ))}
                  </div>
                )}

                {lookupResult.matchedHistory.length > 0 && (
                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
                    <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                      {lang === 'ar' ? 'التطابقات السابقة في السجل الجنائي:' : 'Matched Historical Scans:'}
                    </div>
                    {lookupResult.matchedHistory.map((m) => (
                      <div key={m.analysis_id} className="text-xs font-mono flex items-center justify-between py-1">
                        <span>
                          {m.analysis_id} ({m.sample_type})
                        </span>
                        <span className="font-bold text-rose-500">
                          {m.classification} / {m.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Active Threat Intelligence Feed Sources Summary */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white">
              {lang === 'ar'
                ? 'مصادر استخبارات التهديدات المتصلة وتوقيت آخر تحديث'
                : 'Connected Threat Intelligence Sources & Last Update'}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {lang === 'ar'
                ? 'يتم فصل نتائج الفحص الفعلي عن المزودات غير المهيأة بشفافية كاملة.'
                : 'Actual query statuses are strictly separated from unconfigured external providers.'}
            </p>
          </div>
          <ShieldAlert className="w-5 h-5 text-sky-500" />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-start border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'المصدر / المحرك' : 'Source / Feed'}</th>
                <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الفئة' : 'Category'}</th>
                <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الحالة الفعلية' : 'Actual Status'}</th>
                <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'آخر تحقق' : 'Last Checked'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {providers.map((p) => (
                <tr key={p.id}>
                  <td className="py-3 px-3 font-semibold text-slate-900 dark:text-slate-100">{p.name}</td>
                  <td className="py-3 px-3 text-slate-600 dark:text-slate-400">{p.category}</td>
                  <td className="py-3 px-3 font-mono">
                    <span
                      className={`inline-flex items-center gap-1 font-semibold ${
                        p.configured ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'
                      }`}
                    >
                      {p.configured ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                      <span>{p.configured ? 'ONLINE' : 'NOT_CONFIGURED'}</span>
                    </span>
                  </td>
                  <td className="py-3 px-3 font-mono text-slate-500">{p.lastCheck || 'غير متاح'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
