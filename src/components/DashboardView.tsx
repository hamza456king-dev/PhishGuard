import React from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowUpLeft,
  FolderKanban,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  AnalysisMode,
  PhishGuardReport,
  SampleType,
  SeverityLevel,
  ThreatIntelProviderStatus,
} from '../types/phishguard';
import { getClassificationMeta, getSeverityColor } from './ReportView';

interface DashboardViewProps {
  lang: 'ar' | 'en';
  scans: PhishGuardReport[];
  providers: ThreatIntelProviderStatus[];
  onOpenScanner: (mode: AnalysisMode) => void;
  onSelectReport: (report: PhishGuardReport) => void;
  onOpenHistoryReports: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  lang,
  scans,
  providers,
  onOpenScanner,
  onSelectReport,
  onOpenHistoryReports,
}) => {
  const total = scans.length;
  const safeCount = scans.filter((s) => s.classification === 'SAFE').length;
  const suspiciousCount = scans.filter((s) => s.classification === 'SUSPICIOUS').length;
  const phishingCount = scans.filter((s) => s.classification === 'PHISHING').length;
  const maliciousCount = scans.filter((s) => s.classification === 'MALICIOUS').length;
  const unknownCount = scans.filter((s) => s.classification === 'UNKNOWN').length;
  const criticalCount = scans.filter((s) => s.severity === 'CRITICAL').length;

  const bySeverity: Record<SeverityLevel, number> = {
    CRITICAL: scans.filter((s) => s.severity === 'CRITICAL').length,
    HIGH: scans.filter((s) => s.severity === 'HIGH').length,
    MEDIUM: scans.filter((s) => s.severity === 'MEDIUM').length,
    LOW: scans.filter((s) => s.severity === 'LOW').length,
    INFO: scans.filter((s) => s.severity === 'INFO').length,
  };

  const byType: Record<SampleType, number> = {
    URL: scans.filter((s) => s.sample_type === 'URL').length,
    MESSAGE: scans.filter((s) => s.sample_type === 'MESSAGE').length,
    EMAIL: scans.filter((s) => s.sample_type === 'EMAIL').length,
    FILE: scans.filter((s) => s.sample_type === 'FILE').length,
    IMAGE: scans.filter((s) => s.sample_type === 'IMAGE').length,
  };

  const importantDetections = scans
    .filter((s) => s.classification === 'MALICIOUS' || s.classification === 'PHISHING' || s.severity === 'CRITICAL')
    .slice(0, 4);

  const kpiCards = [
    {
      labelAr: 'إجمالي العينات المفحوصة',
      labelEn: 'Total Analyzed Samples',
      value: total,
      subAr: `${criticalCount} تهديد حرج (CRITICAL)`,
      subEn: `${criticalCount} Critical severity`,
      color: 'text-slate-900 dark:text-white',
    },
    {
      labelAr: 'عينات آمنة (SAFE)',
      labelEn: 'Safe Samples (SAFE)',
      value: safeCount,
      subAr: 'لا توجد مؤشرات خطر مرصودة',
      subEn: 'No threat indicators found',
      color: 'text-emerald-600 dark:text-emerald-400',
    },
    {
      labelAr: 'عينات مشبوهة (SUSPICIOUS)',
      labelEn: 'Suspicious Samples',
      value: suspiciousCount,
      subAr: 'مؤشرات تستوجب الحذر',
      subEn: 'Anomalies requiring caution',
      color: 'text-amber-600 dark:text-amber-400',
    },
    {
      labelAr: 'اكتشافات التصيد (PHISHING)',
      labelEn: 'Phishing Detections',
      value: phishingCount,
      subAr: 'انتحال هوية وسرقة بيانات اعتماد',
      subEn: 'Brand spoofing & credential lures',
      color: 'text-rose-600 dark:text-rose-400',
    },
    {
      labelAr: 'عينات خبيثة (MALICIOUS)',
      labelEn: 'Malicious Samples',
      value: maliciousCount,
      subAr: 'برمجيات أو مرفقات أو سكربتات ضارة',
      subEn: 'Malicious macros, scripts, payloads',
      color: 'text-red-600 dark:text-red-400',
    },
    {
      labelAr: 'غير معروف (UNKNOWN)',
      labelEn: 'Unknown / Unverified',
      value: unknownCount,
      subAr: 'أدلة غير حاسمة أو صيغة غير مدعومة',
      subEn: 'Insufficient data or unsupported type',
      color: 'text-slate-600 dark:text-slate-300',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Hero Banner */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
            {lang === 'ar'
              ? 'لوحة التحكم المركزية — PhishGuard SOC Overview'
              : 'PhishGuard Central Security Dashboard'}
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1 max-w-3xl">
            {lang === 'ar'
              ? 'ملخص تنفيذي مباشر لجميع العينات المفحوصة، وتوزيع مستويات الخطورة، ونشاط التحليل عبر الوقت، وأبرز التهديدات المكتشفة، وحالة محركات النظام الفعلية.'
              : 'Real-time overview of analyzed samples, threat severity distribution, analysis activity over time, critical detections, and actual system engine health.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => onOpenScanner('URL')}
            className="px-4 py-2.5 text-xs font-semibold rounded-lg bg-sky-600 hover:bg-sky-500 text-white transition-colors whitespace-nowrap shrink-0"
          >
            {lang === 'ar' ? 'فتح مركز التحليل (Analysis Center)' : 'Open Analysis Center'}
          </button>
          <button
            type="button"
            onClick={() => onOpenScanner('MULTI_INPUT_CASE')}
            className="inline-flex items-center gap-1.5 px-4 py-2.5 text-xs font-semibold rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-900 dark:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
          >
            <FolderKanban className="w-3.5 h-3.5 text-sky-500" />
            <span>{lang === 'ar' ? 'فحص قضية متعددة المدخلات' : 'New Multi-Input Case'}</span>
          </button>
        </div>
      </div>

      {/* 6 KPI Stat Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {kpiCards.map((card, i) => (
          <div
            key={i}
            className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 flex flex-col justify-between"
          >
            <div className="text-xs font-medium text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? card.labelAr : card.labelEn}
            </div>
            <div className={`mt-2 text-2xl font-bold font-mono tabular-nums ${card.color}`}>
              {card.value}
            </div>
            <div className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? card.subAr : card.subEn}
            </div>
          </div>
        ))}
      </div>

      {/* Threat Severity Distribution + Analysis Activity Over Time + Important Detections */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 1. Threat Severity Distribution */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 flex flex-col justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 mb-4">
              {lang === 'ar' ? 'توزيع مستويات الخطورة (Threat Severity Distribution)' : 'Threat Severity Distribution'}
            </h2>
            <div className="space-y-3">
              {[
                { label: 'CRITICAL (حرج)', count: bySeverity.CRITICAL, barColor: 'bg-red-600' },
                { label: 'HIGH (مرتفع)', count: bySeverity.HIGH, barColor: 'bg-rose-500' },
                { label: 'MEDIUM (متوسط)', count: bySeverity.MEDIUM, barColor: 'bg-amber-500' },
                { label: 'LOW (منخفض)', count: bySeverity.LOW, barColor: 'bg-sky-500' },
                { label: 'INFO (معلوماتي / آمن)', count: bySeverity.INFO, barColor: 'bg-emerald-500' },
              ].map((row) => {
                const pct = total > 0 ? Math.round((row.count / total) * 100) : 0;
                return (
                  <div key={row.label} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-medium text-slate-700 dark:text-slate-300">{row.label}</span>
                      <span className="font-mono tabular-nums text-slate-600 dark:text-slate-400">
                        {row.count} ({pct}%)
                      </span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                      <div className={`h-full ${row.barColor}`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800">
            <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
              {lang === 'ar' ? 'مؤشرات حالة النظام الفعلية (Actual System Status):' : 'Actual System Status Indicators:'}
            </div>
            <div className="space-y-1.5 text-xs">
              {providers.slice(0, 4).map((p) => (
                <div key={p.id} className="flex items-center justify-between">
                  <span className="text-slate-600 dark:text-slate-400 truncate">{p.name}</span>
                  <span
                    className={`font-mono text-[11px] ${
                      p.configured ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'
                    }`}
                  >
                    {p.configured ? (lang === 'ar' ? 'ONLINE' : 'ONLINE') : 'NOT_CONFIGURED'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* 2. Analysis Activity by Vector & Over Time */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                {lang === 'ar' ? 'نشاط الفحص حسب نوع العينة والوقت' : 'Analysis Activity Over Time & Vector'}
              </h2>
              <Activity className="w-4 h-4 text-sky-500" />
            </div>

            <div className="space-y-3">
              {(['URL', 'MESSAGE', 'EMAIL', 'FILE', 'IMAGE'] as SampleType[]).map((st) => {
                const count = byType[st];
                const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                return (
                  <div
                    key={st}
                    className="p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 flex items-center justify-between"
                  >
                    <div>
                      <div className="text-xs font-bold font-mono text-slate-900 dark:text-slate-100">{st}</div>
                      <div className="text-[11px] text-slate-500">
                        {lang === 'ar' ? `نسبة الفحوص: ${pct}%` : `Share: ${pct}%`}
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-sm font-bold font-mono tabular-nums text-sky-600 dark:text-sky-400">
                        {count}
                      </span>
                      <button
                        type="button"
                        onClick={() => onOpenScanner(st)}
                        className="text-xs font-semibold text-slate-700 dark:text-slate-300 hover:text-sky-500 inline-flex items-center gap-0.5"
                      >
                        <span>{lang === 'ar' ? 'فحص' : 'Scan'}</span>
                        <ArrowUpLeft className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs text-slate-500">
            <span>
              {lang === 'ar'
                ? `آخر نشاط مسجل: ${scans[0]?.analyzed_at ? new Date(scans[0].analyzed_at).toLocaleTimeString() : 'لا يوجد'}`
                : `Latest scan: ${scans[0]?.analyzed_at ? new Date(scans[0].analyzed_at).toLocaleTimeString() : 'None'}`}
            </span>
            <button
              type="button"
              onClick={onOpenHistoryReports}
              className="text-sky-600 dark:text-sky-400 font-semibold hover:underline"
            >
              {lang === 'ar' ? 'السجل الكامل ←' : 'Full History →'}
            </button>
          </div>
        </div>

        {/* 3. Recent Important Detections */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                {lang === 'ar' ? 'أبرز التهديدات المكتشفة مؤخراً' : 'Recent Important Detections'}
              </h2>
              <ShieldAlert className="w-4 h-4 text-rose-500" />
            </div>

            {importantDetections.length === 0 ? (
              <div className="p-6 text-center rounded-lg border border-dashed border-slate-200 dark:border-slate-800 text-xs text-slate-500">
                <ShieldCheck className="w-6 h-6 text-emerald-500 mx-auto mb-2" />
                {lang === 'ar'
                  ? 'لا توجد اكتشافات حرجة أو تصيد مؤكدة حالياً.'
                  : 'No critical or confirmed phishing detections recorded yet.'}
              </div>
            ) : (
              <div className="space-y-2.5">
                {importantDetections.map((det) => (
                  <div
                    key={det.analysis_id}
                    className="p-3 rounded-lg border border-rose-500/25 bg-rose-500/5 hover:border-rose-500/50 transition-colors"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono font-bold text-rose-600 dark:text-rose-400">
                        {det.classification} • {det.severity}
                      </span>
                      <span className="font-mono text-[11px] text-slate-500">{det.sample_type}</span>
                    </div>
                    <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate mt-1">
                      {det.sample_name}
                    </div>
                    <div className="flex items-center justify-between mt-2">
                      <span className="text-[11px] text-slate-500 truncate max-w-[180px]">
                        {det.threat_types[0] || det.analysis_id}
                      </span>
                      <button
                        type="button"
                        onClick={() => onSelectReport(det)}
                        className="text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline"
                      >
                        {lang === 'ar' ? 'التقرير الجنائي' : 'Inspect'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Security Analyses Table */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
            {lang === 'ar' ? 'النشاط الأمني الحديث (Recent Analysis Activity)' : 'Recent Analysis Activity'}
          </h2>
          <button
            type="button"
            onClick={onOpenHistoryReports}
            className="text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline"
          >
            {lang === 'ar' ? `عرض السجل والتقارير (${scans.length})` : `View All History & Reports (${scans.length})`}
          </button>
        </div>

        {scans.length === 0 ? (
          <div className="p-8 text-center rounded-xl border border-dashed border-slate-200 dark:border-slate-800">
            <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto mb-2" />
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
              {lang === 'ar' ? 'لا توجد سجلات فحص حتى الآن' : 'No Analysis Records Yet'}
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-md mx-auto">
              {lang === 'ar'
                ? 'انتقل إلى مركز التحليل لفحص رابط أو رسالة أو بريد إلكتروني أو ملف أو صورة، وستظهر النتائج الحقيقية هنا فوراً.'
                : 'Open the Analysis Center to scan a URL, message, email, file, or image. Real database results will appear here immediately.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-start border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'المعرّف' : 'ID'}</th>
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'النوع' : 'Type'}</th>
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'العينة' : 'Sample'}</th>
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'التصنيف الأمني' : 'Classification'}</th>
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'الخطورة' : 'Severity'}</th>
                  <th className="py-2.5 px-3 text-start font-medium">{lang === 'ar' ? 'حالة الرابط' : 'Link Status'}</th>
                  <th className="py-2.5 px-3 text-end font-medium">{lang === 'ar' ? 'الثقة' : 'Confidence'}</th>
                  <th className="py-2.5 px-3 text-end font-medium">{lang === 'ar' ? 'التقرير' : 'Report'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {scans.slice(0, 8).map((s) => {
                  const meta = getClassificationMeta(s.classification, lang);
                  return (
                    <tr
                      key={s.analysis_id}
                      className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                    >
                      <td className="py-3 px-3 font-mono text-xs text-slate-600 dark:text-slate-400">
                        {s.analysis_id}
                      </td>
                      <td className="py-3 px-3 font-mono text-xs text-slate-700 dark:text-slate-300">
                        {s.sample_type}
                      </td>
                      <td className="py-3 px-3 text-xs font-medium text-slate-900 dark:text-slate-100 max-w-xs truncate" title={s.sample_name}>
                        {s.sample_name}
                      </td>
                      <td className={`py-3 px-3 text-xs font-bold ${meta.colorClass}`}>
                        {meta.shortLabel}
                      </td>
                      <td className={`py-3 px-3 font-mono text-xs ${getSeverityColor(s.severity)}`}>
                        {s.severity}
                      </td>
                      <td className="py-3 px-3 font-mono text-xs text-slate-600 dark:text-slate-400">
                        {s.link_status}
                      </td>
                      <td className="py-3 px-3 text-end font-mono tabular-nums text-xs text-slate-700 dark:text-slate-300">
                        {s.confidence}%
                      </td>
                      <td className="py-3 px-3 text-end">
                        <button
                          type="button"
                          onClick={() => onSelectReport(s)}
                          className="text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap"
                        >
                          {lang === 'ar' ? 'عرض التقرير' : 'View Report'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
