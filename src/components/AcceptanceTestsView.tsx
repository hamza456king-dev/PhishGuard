import React, { useState } from 'react';
import { CheckCircle2, Loader2, Play, ShieldCheck, XCircle } from 'lucide-react';
import { MANDATORY_ACCEPTANCE_TESTS } from '../engine/acceptanceCases';
import { AcceptanceTestCase, PhishGuardReport } from '../types/phishguard';
import { ReportView, getClassificationMeta } from './ReportView';

interface AcceptanceTestsViewProps {
  lang: 'ar' | 'en';
  onScanCompleted: (report: PhishGuardReport) => void;
}

interface TestExecutionResult {
  testCase: AcceptanceTestCase;
  report: PhishGuardReport;
  passed: boolean;
}

export const AcceptanceTestsView: React.FC<AcceptanceTestsViewProps> = ({
  lang,
  onScanCompleted,
}) => {
  const [runningAll, setRunningAll] = useState(false);
  const [runningSingleId, setRunningSingleId] = useState<string | null>(null);
  const [resultsMap, setResultsMap] = useState<Record<string, TestExecutionResult>>({});
  const [selectedReport, setSelectedReport] = useState<PhishGuardReport | null>(null);

  const handleRunAllTests = async () => {
    setRunningAll(true);
    try {
      const res = await fetch('/api/tests/run-all', { method: 'POST' });
      const data = await res.json();
      if (data.results && Array.isArray(data.results)) {
        const nextMap: Record<string, TestExecutionResult> = {};
        for (const item of data.results as TestExecutionResult[]) {
          nextMap[item.testCase.id] = item;
        }
        setResultsMap(nextMap);
        if (data.results.length > 0) {
          setSelectedReport(data.results[data.results.length - 1].report);
        }
      }
    } finally {
      setRunningAll(false);
    }
  };

  const handleRunSingleTest = async (tc: AcceptanceTestCase) => {
    setRunningSingleId(tc.id);
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sampleType: tc.sampleType,
          sampleName: tc.titleAr,
          ...tc.payload,
          consentExternal: false,
          useGeminiEnrichment: false,
        }),
      });
      const report = (await res.json()) as PhishGuardReport;
      const passed =
        tc.expectedClassification.includes(report.classification) &&
        (!tc.expectedLinkStatus || tc.expectedLinkStatus.includes(report.link_status));

      setResultsMap((prev) => ({
        ...prev,
        [tc.id]: { testCase: tc, report, passed },
      }));
      setSelectedReport(report);
      onScanCompleted(report);
    } finally {
      setRunningSingleId(null);
    }
  };

  const executedList = Object.values(resultsMap);
  const passedCount = executedList.filter((r) => r.passed).length;

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white">
              {lang === 'ar'
                ? 'مصفوفة اختبارات القبول الأمنية الـ 13 (Mandatory Readiness Verification Suite)'
                : '13 Mandatory Cybersecurity Acceptance Tests'}
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              {lang === 'ar'
                ? 'تحقق عملي مباشر من الحالات الـ 13 المطلوبة (بما في ذلك كشف Homoglyphs، سلاسل التوجيه، مصادقة DMARC، ماكرو Office، سكربتات داخل ZIP، تصيد QR، وتصنيف الملفات غير المدعومة كـ UNKNOWN وليس SAFE).'
                : 'Live verification of all 13 mandatory forensic scenarios against the server-side analysis engine.'}
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {executedList.length > 0 && (
              <span className="text-xs font-mono tabular-nums font-bold text-emerald-600 dark:text-emerald-400">
                {lang === 'ar'
                  ? `اجتاز ${passedCount} من ${executedList.length} اختبار`
                  : `Passed ${passedCount} / ${executedList.length}`}
              </span>
            )}
            <button
              type="button"
              disabled={runningAll}
              onClick={handleRunAllTests}
              className="inline-flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white transition-colors whitespace-nowrap shrink-0"
            >
              {runningAll ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
              <span>
                {lang === 'ar' ? 'تشغيل جميع الاختبارات الـ 13 الآن' : 'Execute All 13 Verification Tests'}
              </span>
            </button>
          </div>
        </div>

        <div className="mt-6 overflow-x-auto">
          <table className="w-full text-start border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                <th className="py-2.5 px-3 text-start font-medium">#</th>
                <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'حالة الاختبار' : 'Test Scenario'}</th>
                <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'النوع' : 'Type'}</th>
                <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'النتيجة المتوقعة' : 'Expected'}</th>
                <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'النتيجة الفعلية' : 'Actual Verdict'}</th>
                <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'الحالة' : 'Status'}</th>
                <th className="py-2.5 px-3 text-end font-medium">{lang === 'ar' ? 'إجراء' : 'Action'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {MANDATORY_ACCEPTANCE_TESTS.map((tc) => {
                const res = resultsMap[tc.id];
                const isRunning = runningSingleId === tc.id;
                const actualMeta = res ? getClassificationMeta(res.report.classification, lang) : null;

                return (
                  <tr key={tc.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                    <td className="py-3 px-3 font-mono text-xs text-slate-500">{tc.number}</td>
                    <td className="py-3 px-3">
                      <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                        {lang === 'ar' ? tc.titleAr : tc.titleEn}
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                        {tc.descriptionAr}
                      </div>
                    </td>
                    <td className="py-3 px-3 font-mono text-xs text-slate-600 dark:text-slate-400">
                      {tc.sampleType}
                    </td>
                    <td className="py-3 px-3 font-mono text-xs text-slate-700 dark:text-slate-300">
                      {tc.expectedClassification.join(' / ')}
                      {tc.expectedLinkStatus ? ` (${tc.expectedLinkStatus.join('/')})` : ''}
                    </td>
                    <td className="py-3 px-3 font-mono text-xs">
                      {res && actualMeta ? (
                        <span className={`font-bold ${actualMeta.colorClass}`}>
                          {res.report.classification} ({res.report.link_status})
                        </span>
                      ) : (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-xs">
                      {res ? (
                        res.passed ? (
                          <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400 font-semibold">
                            <CheckCircle2 className="w-4 h-4" />
                            <span>PASS</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-red-600 dark:text-red-400 font-semibold">
                            <XCircle className="w-4 h-4" />
                            <span>FAIL</span>
                          </span>
                        )
                      ) : (
                        <span className="text-slate-400">{lang === 'ar' ? 'جاهز للفحص' : 'Ready'}</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-end">
                      <div className="inline-flex items-center gap-2">
                        {res && (
                          <button
                            type="button"
                            onClick={() => setSelectedReport(res.report)}
                            className="text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap"
                          >
                            {lang === 'ar' ? 'عرض التقرير' : 'View Report'}
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={isRunning || runningAll}
                          onClick={() => handleRunSingleTest(tc)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap"
                        >
                          {isRunning ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                          <span>{lang === 'ar' ? 'اختبار' : 'Run'}</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {selectedReport && <ReportView report={selectedReport} lang={lang} />}
    </div>
  );
};
