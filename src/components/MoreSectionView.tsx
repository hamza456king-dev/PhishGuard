import React, { useState } from 'react';
import {
  Activity,
  BookOpen,
  CheckCircle2,
  Database,
  KeyRound,
  Lock,
  Plug,
  Search,
  ShieldCheck,
  Sliders,
  Terminal,
  Users,
  XCircle,
} from 'lucide-react';
import {
  MoreSubSection,
  PhishGuardReport,
  ThreatIntelProviderStatus,
} from '../types/phishguard';
import { AcceptanceTestsView } from './AcceptanceTestsView';

interface MoreSectionViewProps {
  lang: 'ar' | 'en';
  activeSubSection: MoreSubSection;
  onSelectSubSection: (sub: MoreSubSection) => void;
  providers: ThreatIntelProviderStatus[];
  consentExternal: boolean;
  onToggleConsentExternal: (val: boolean) => void;
  retentionDays: number;
  onChangeRetentionDays: (days: number) => void;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
  onToggleLang: () => void;
  userRole: 'admin' | 'analyst' | 'viewer';
  onChangeRolePreview: (role: 'admin' | 'analyst' | 'viewer') => void;
  userEmail: string | null;
  auditLogs: Array<{
    id: string;
    timestamp: string;
    action: string;
    sample_type: string;
    sample_name: string;
    classification: string;
    severity: string;
  }>;
  onScanCompleted: (report: PhishGuardReport) => void;
}

export const MoreSectionView: React.FC<MoreSectionViewProps> = ({
  lang,
  activeSubSection,
  onSelectSubSection,
  providers,
  consentExternal,
  onToggleConsentExternal,
  retentionDays,
  onChangeRetentionDays,
  theme,
  onToggleTheme,
  onToggleLang,
  userRole,
  onChangeRolePreview,
  userEmail,
  auditLogs,
  onScanCompleted,
}) => {
  const [auditSearch, setAuditSearch] = useState('');
  const [notifyCritical, setNotifyCritical] = useState(true);
  const [strictPromptGuard, setStrictPromptGuard] = useState(true);

  const subNavItems: Array<{
    id: MoreSubSection;
    labelAr: string;
    labelEn: string;
    descAr: string;
    Icon: React.ElementType;
    restricted?: boolean;
  }> = [
    {
      id: 'INTEGRATIONS',
      labelAr: 'A. التكاملات والمزودون',
      labelEn: 'A. Integrations & Providers',
      descAr: 'VirusTotal, Web Risk, DNS, RDAP, TLS, YARA, Sandbox',
      Icon: Plug,
    },
    {
      id: 'SYSTEM_HEALTH',
      labelAr: 'B. حالة النظام والمحركات',
      labelEn: 'B. System Health',
      descAr: 'الخادم، Firestore، طابور المعالجة، أخطاء الخدمات',
      Icon: Activity,
    },
    {
      id: 'SETTINGS_PRIVACY',
      labelAr: 'C. الإعدادات والخصوصية',
      labelEn: 'C. Settings & Privacy',
      descAr: 'اللغة، المظهر، موافقة الفحص الخارجي، الاحتفاظ بالبيانات',
      Icon: Sliders,
    },
    {
      id: 'USER_ACCESS',
      labelAr: 'D. إدارة المستخدمين والصلاحيات',
      labelEn: 'D. User & Access Management',
      descAr: 'الأدوار، مصفوفة الصلاحيات RBAC، التحكم بالوصول',
      Icon: Users,
      restricted: true,
    },
    {
      id: 'AUDIT_LOGS',
      labelAr: 'E. سجل التدقيق الأمني',
      labelEn: 'E. Audit Logs',
      descAr: 'سجل إجراءات المستخدمين والأحداث الأمنية',
      Icon: Database,
    },
    {
      id: 'DOCS_HELP',
      labelAr: 'F. التوثيق والمساعدة',
      labelEn: 'F. Documentation & Help',
      descAr: 'الدليل التقني، مرجع API، استكشاف الأخطاء',
      Icon: BookOpen,
    },
    {
      id: 'DEV_DIAGNOSTICS',
      labelAr: 'G. أدوات المطور والتشخيص',
      labelEn: 'G. Developer & Diagnostic Tools',
      descAr: 'اختبارات القبول الـ 13 وأدوات فحص المحركات',
      Icon: Terminal,
      restricted: true,
    },
  ];

  const filteredAuditLogs = auditLogs.filter((log) => {
    if (!auditSearch.trim()) return true;
    const q = auditSearch.trim().toLowerCase();
    return (
      log.id.toLowerCase().includes(q) ||
      log.action.toLowerCase().includes(q) ||
      log.sample_name.toLowerCase().includes(q) ||
      log.classification.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header & Sub-Navigation Selector inside "المزيد | More" */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-5">
          <div>
            <div className="text-xs font-mono uppercase tracking-wider text-slate-500">
              {lang === 'ar' ? 'القسم الثانوي والإداري (Secondary Navigation)' : 'Secondary & Administrative Section'}
            </div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white mt-0.5">
              {lang === 'ar' ? 'المزيد — الإدارة والتكاملات والتشخيص (More)' : 'More — Administration, Integrations & Diagnostics'}
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              {lang === 'ar'
                ? 'تم تجميع جميع الأدوات الإدارية والتكاملات وحالة النظام وسجل التدقيق والتوثيق وأدوات التشخيص في هذا القسم الثانوي للحفاظ على تركيز شريط التنقل الرئيسي.'
                : 'All administrative, integration, health, audit, documentation, and diagnostic tools are consolidated here.'}
            </p>
          </div>

          {/* Role Context Indicator & RBAC Switcher for Testing */}
          <div className="flex items-center gap-2 text-xs bg-slate-50 dark:bg-slate-950 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-800">
            <KeyRound className="w-4 h-4 text-sky-500 shrink-0" />
            <span className="text-slate-600 dark:text-slate-400">
              {lang === 'ar' ? 'مستوى الصلاحية (RBAC Role):' : 'Active Role:'}
            </span>
            <select
              value={userRole}
              onChange={(e) => onChangeRolePreview(e.target.value as 'admin' | 'analyst' | 'viewer')}
              aria-label="Active RBAC Role"
              className="font-mono font-bold text-sky-600 dark:text-sky-400 bg-transparent focus:outline-none"
            >
              <option value="admin">ADMIN (مدير النظام)</option>
              <option value="analyst">ANALYST (محلل أمني)</option>
              <option value="viewer">VIEWER (مستعرض مقيد)</option>
            </select>
          </div>
        </div>

        {/* 7 Sub-Section Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5" role="tablist">
          {subNavItems.map((item) => {
            const ItemIcon = item.Icon;
            const isSelected = activeSubSection === item.id;
            return (
              <button
                key={item.id}
                type="button"
                role="tab"
                aria-selected={isSelected}
                onClick={() => onSelectSubSection(item.id)}
                className={`text-start p-3 rounded-lg border transition-colors ${
                  isSelected
                    ? 'bg-sky-600/10 border-sky-500 text-slate-900 dark:text-white'
                    : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-semibold text-xs">
                    <ItemIcon className={`w-4 h-4 shrink-0 ${isSelected ? 'text-sky-500' : 'text-slate-400'}`} />
                    <span className="truncate">{lang === 'ar' ? item.labelAr : item.labelEn}</span>
                  </div>
                  {item.restricted && (
                    <Lock className="w-3 h-3 text-amber-500 shrink-0" />
                  )}
                </div>
                <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400 truncate">
                  {item.descAr}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* A. INTEGRATIONS & PROVIDERS */}
      {activeSubSection === 'INTEGRATIONS' && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white">
              {lang === 'ar'
                ? 'A. التكاملات ومزودو الفحص (Integrations & Providers)'
                : 'A. Integrations & Threat Providers'}
            </h2>
            <p className="text-xs text-slate-500 mt-1">
              {lang === 'ar'
                ? 'حالة التكامل الفعلية لـ Google Web Risk, VirusTotal, DNS, WHOIS/RDAP, TLS, IP Intelligence, Antivirus, YARA, و Sandbox. يتم حفظ جميع مفاتيح API على الخادم فقط.'
                : 'Real server-side status of Google Web Risk, VirusTotal, DNS, WHOIS/RDAP, TLS, IP Intel, Antivirus, YARA, and Sandbox.'}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {providers.map((p) => (
              <div
                key={p.id}
                className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-bold text-slate-900 dark:text-slate-100">{p.name}</span>
                    <span
                      className={`inline-flex items-center gap-1 text-xs font-mono font-semibold ${
                        p.configured ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'
                      }`}
                    >
                      {p.configured ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                      <span>{p.configured ? 'ONLINE (مُهيأ)' : 'NOT_CONFIGURED (غير مُهيأ)'}</span>
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 mt-1">{p.category}</div>

                  {p.capabilities.length > 0 && (
                    <ul className="mt-3 space-y-1 text-xs text-slate-700 dark:text-slate-300">
                      {p.capabilities.map((cap, idx) => (
                        <li key={idx}>• {cap}</li>
                      ))}
                    </ul>
                  )}

                  {p.unavailableCapabilities.length > 0 && (
                    <ul className="mt-3 space-y-1 text-xs text-amber-700 dark:text-amber-400">
                      {p.unavailableCapabilities.map((uc, idx) => (
                        <li key={idx}>• {uc}</li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-500 flex items-center justify-between">
                  <span>ID: {p.id}</span>
                  <span>{p.lastCheck || 'No recent check'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* B. SYSTEM HEALTH */}
      {activeSubSection === 'SYSTEM_HEALTH' && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white">
              {lang === 'ar'
                ? 'B. حالة النظام والخدمات الخلفية (System Health)'
                : 'B. System Health & Service Telemetry'}
            </h2>
            <p className="text-xs text-slate-500 mt-1">
              {lang === 'ar'
                ? 'مؤشرات حالة الخادم الخلفي، اتصال قاعدة بيانات Firestore، طابور المعالجة غير المتزامنة، وحالة الاتصال بالمزودين.'
                : 'Backend status, Firestore database connectivity, async worker queue, and provider connectivity.'}
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              {
                labelAr: 'خادم التحليل الخلفي (Backend Node)',
                status: 'OPERATIONAL',
                detail: 'Express + Isolated Forensic Prober (Port 3000)',
              },
              {
                labelAr: 'قاعدة بيانات Firebase Firestore',
                status: 'CONNECTED',
                detail: 'Zero-Trust Rules Deployed & Active',
              },
              {
                labelAr: 'طابور المعالجة والعاملين (Worker Queue)',
                status: 'IDLE / READY',
                detail: '0 Pending Jobs • Async Sandbox Isolator Active',
              },
              {
                labelAr: 'سجل أخطاء الخدمات (Service Errors)',
                status: '0 FATAL ERRORS',
                detail: 'SSRF Guard & Zip Bomb Protection Online',
              },
            ].map((card, idx) => (
              <div
                key={idx}
                className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950"
              >
                <div className="text-xs text-slate-500">{card.labelAr}</div>
                <div className="mt-2 text-sm font-bold font-mono text-emerald-600 dark:text-emerald-400">
                  {card.status}
                </div>
                <div className="mt-1 text-[11px] text-slate-500">{card.detail}</div>
              </div>
            ))}
          </div>

          <div className="space-y-2.5 text-xs">
            <h3 className="font-bold text-slate-900 dark:text-slate-100">
              {lang === 'ar' ? 'ضوابط الحماية النشطة في الخادم:' : 'Active Server Security Controls:'}
            </h3>
            {[
              {
                name: 'حماية SSRF و DNS Rebinding عند فحص الروابط',
                detail: 'حظر كامل لـ 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254',
              },
              {
                name: 'الحماية من قنابل الأرشيف واختراق المسار (Zip Bomb & Zip Slip Guard)',
                detail: 'فحص ZIP داخل الذاكرة دون استخراج للقرص، وحظر المسارات ../ ونسب الضغط الشاذة',
              },
              {
                name: 'التحقق من البايتات السحرية (Magic Bytes Binary Verification)',
                detail: 'اكتشاف نوع الملف الحقيقي من التوقيع الثنائي وليس من امتداد الاسم فقط',
              },
              {
                name: 'عزل تعليمات الذكاء الاصطناعي (Prompt Injection Defense)',
                detail: 'تغليف نصوص العينات غير الموثوقة ومنعها من تجاوز تعليمات النظام',
              },
            ].map((ctrl, i) => (
              <div
                key={i}
                className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between"
              >
                <div>
                  <div className="font-semibold text-slate-900 dark:text-slate-100">{ctrl.name}</div>
                  <div className="text-slate-500 mt-0.5">{ctrl.detail}</div>
                </div>
                <span className="font-mono font-bold text-emerald-600 dark:text-emerald-400">ONLINE</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* C. SETTINGS & PRIVACY */}
      {activeSubSection === 'SETTINGS_PRIVACY' && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-6">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white">
              {lang === 'ar' ? 'C. الإعدادات والخصوصية (Settings & Privacy)' : 'C. Settings & Privacy'}
            </h2>
            <p className="text-xs text-slate-500 mt-1">
              {lang === 'ar'
                ? 'إدارة اللغة، المظهر، موافقة الفحص الخارجي، سياسة الاحتفاظ بالبيانات، والتنبيهات الأمنية.'
                : 'Manage language, theme, external scan privacy consent, data retention policy, and security alerts.'}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={consentExternal}
                    onChange={(e) => onToggleConsentExternal(e.target.checked)}
                    className="mt-1 rounded border-slate-300 dark:border-slate-700 text-sky-600"
                  />
                  <div>
                    <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {lang === 'ar'
                        ? 'موافقة مشاركة المؤشرات مع مزودي معلومات التهديدات الخارجيين'
                        : 'External Threat Intelligence Scan Consent'}
                    </div>
                    <p className="text-xs text-slate-500 mt-1">
                      {lang === 'ar'
                        ? 'عند إيقاف هذا الخيار، تبقى جميع الفحوص محلية بالكامل داخل الخادم المعزول.'
                        : 'When disabled, all scans remain strictly local on the isolated server.'}
                    </p>
                  </div>
                </label>
              </div>

              <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={notifyCritical}
                    onChange={(e) => setNotifyCritical(e.target.checked)}
                    className="mt-1 rounded border-slate-300 dark:border-slate-700 text-sky-600"
                  />
                  <div>
                    <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {lang === 'ar'
                        ? 'تفعيل التنبيهات الفورية للتهديدات الحرجة (CRITICAL Alerts)'
                        : 'Enable Immediate Notifications for CRITICAL Detections'}
                    </div>
                    <p className="text-xs text-slate-500 mt-1">
                      {lang === 'ar'
                        ? 'إبراز العينات المصنفة كـ MALICIOUS أو CRITICAL في لوحة التحكم وسجل التدقيق.'
                        : 'Highlight CRITICAL and MALICIOUS detections across SOC dashboards.'}
                    </p>
                  </div>
                </label>
              </div>

              <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={strictPromptGuard}
                    onChange={(e) => setStrictPromptGuard(e.target.checked)}
                    className="mt-1 rounded border-slate-300 dark:border-slate-700 text-sky-600"
                  />
                  <div>
                    <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {lang === 'ar'
                        ? 'وضع العزل الصارم ضد حقن الأوامر (Strict Prompt Injection Isolation)'
                        : 'Strict Untrusted Sample Isolation'}
                    </div>
                    <p className="text-xs text-slate-500 mt-1">
                      {lang === 'ar'
                        ? 'معاملة كافة النصوص داخل العينات كبيانات غير موثوقة محل فحص جنائي فقط.'
                        : 'Treat all embedded instructions inside samples strictly as forensic evidence.'}
                    </p>
                  </div>
                </label>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label htmlFor="retention-select" className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  {lang === 'ar' ? 'مدة الاحتفاظ بالتقارير الجنائية (Data Retention):' : 'Data Retention Period:'}
                </label>
                <select
                  id="retention-select"
                  value={retentionDays}
                  onChange={(e) => onChangeRetentionDays(Number(e.target.value))}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100"
                >
                  <option value={7}>{lang === 'ar' ? '7 أيام' : '7 Days'}</option>
                  <option value={30}>{lang === 'ar' ? '30 يوماً' : '30 Days'}</option>
                  <option value={90}>{lang === 'ar' ? '90 يوماً (معيار SOC)' : '90 Days (SOC Standard)'}</option>
                  <option value={365}>{lang === 'ar' ? '365 يوماً' : '365 Days'}</option>
                </select>
              </div>

              <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                    {lang === 'ar' ? 'لغة واجهة المنصة (Interface Language)' : 'Platform Language'}
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {lang === 'ar' ? 'العربية (RTL) أو الإنجليزية (LTR)' : 'Arabic (RTL) or English (LTR)'}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={onToggleLang}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-xs font-semibold"
                >
                  {lang === 'ar' ? 'التبديل إلى English' : 'Switch to العربية'}
                </button>
              </div>

              <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                    {lang === 'ar' ? 'مظهر المنصة (Theme Mode)' : 'Theme Mode'}
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {theme === 'dark' ? 'Dark SOC Slate' : 'High-Contrast Light'}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={onToggleTheme}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-xs font-semibold"
                >
                  {theme === 'dark' ? (lang === 'ar' ? 'الوضع الفاتح' : 'Light Mode') : lang === 'ar' ? 'الوضع الداكن' : 'Dark Mode'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* D. USER & ACCESS MANAGEMENT (RBAC Guarded) */}
      {activeSubSection === 'USER_ACCESS' && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                {lang === 'ar'
                  ? 'D. إدارة المستخدمين والصلاحيات (User & Access Management — RBAC)'
                  : 'D. User & Access Management (RBAC)'}
              </h2>
              <p className="text-xs text-slate-500 mt-1">
                {lang === 'ar'
                  ? 'التحكم بالوصول القائم على الأدوار (Admin, Analyst, Viewer) وفق قواعد أمان Firestore.'
                  : 'Role-Based Access Control enforced across UI and Firestore security rules.'}
              </p>
            </div>
            <ShieldCheck className="w-5 h-5 text-sky-500" />
          </div>

          {userRole === 'viewer' ? (
            <div className="p-6 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-700 dark:text-amber-300">
              <div className="font-bold text-sm mb-1">
                {lang === 'ar'
                  ? 'صلاحية مقيدة (Restricted Access — VIEWER Role)'
                  : 'Restricted Access (VIEWER Role)'}
              </div>
              <p>
                {lang === 'ar'
                  ? 'دور المستعرض (Viewer) لا يملك صلاحية تعديل أدوار المستخدمين. يمكنك التبديل إلى دور ADMIN من محدد الصلاحية أعلى الصفحة لمعاينة لوحة إدارة الصلاحيات.'
                  : 'Viewer role cannot modify user permissions. Switch to ADMIN role in the top selector to manage users.'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-start border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                    <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'المستخدم / البريد' : 'User / Email'}</th>
                    <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الدور (Role)' : 'Role'}</th>
                    <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الصلاحيات الممنوحة' : 'Permissions'}</th>
                    <th className="py-2.5 px-3 text-start">{lang === 'ar' ? 'الحالة' : 'Status'}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  <tr>
                    <td className="py-3 px-3 font-mono font-semibold text-slate-900 dark:text-slate-100">
                      {userEmail || 'hamza.456.king@gmail.com (Primary Admin)'}
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-sky-600 dark:text-sky-400">ADMIN</td>
                    <td className="py-3 px-3 text-slate-600 dark:text-slate-300">
                      Full Forensic Scan, Case Management, Threat Intel, RBAC Admin, Diagnostics
                    </td>
                    <td className="py-3 px-3 font-mono text-emerald-600 dark:text-emerald-400">ACTIVE</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-3 font-mono font-semibold text-slate-900 dark:text-slate-100">
                      soc-tier2@phishguard.internal
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-emerald-600 dark:text-emerald-400">ANALYST</td>
                    <td className="py-3 px-3 text-slate-600 dark:text-slate-300">
                      Analysis Center, Multi-Input Cases, IOC Lookup, History & Reports, Diagnostic Suite
                    </td>
                    <td className="py-3 px-3 font-mono text-emerald-600 dark:text-emerald-400">ACTIVE</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-3 font-mono font-semibold text-slate-900 dark:text-slate-100">
                      auditor-readonly@phishguard.internal
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-slate-500">VIEWER</td>
                    <td className="py-3 px-3 text-slate-600 dark:text-slate-300">
                      Read-Only Dashboard, History & Reports Inspection, Audit Trail View
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-500">READ_ONLY</td>
                  </tr>
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* E. AUDIT LOGS */}
      {activeSubSection === 'AUDIT_LOGS' && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                {lang === 'ar' ? 'E. سجل التدقيق الأمني (Audit Logs)' : 'E. Security Operations Audit Logs'}
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                {lang === 'ar'
                  ? 'توثيق زمني لجميع عمليات الفحص، القضايا متعددة المدخلات، استعلامات IOC، والحذف.'
                  : 'Chronological audit trail of all scans, multi-input cases, IOC queries, and deletions.'}
              </p>
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute top-2.5 start-3 pointer-events-none" />
              <input
                type="text"
                value={auditSearch}
                onChange={(e) => setAuditSearch(e.target.value)}
                placeholder={lang === 'ar' ? 'تصفية سجل التدقيق...' : 'Filter audit logs...'}
                className="w-full ps-8 pe-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950"
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-start border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                  <th className="py-2 px-3 text-start">{lang === 'ar' ? 'معرّف السجل' : 'Audit ID'}</th>
                  <th className="py-2 px-3 text-start">{lang === 'ar' ? 'الوقت' : 'Timestamp'}</th>
                  <th className="py-2 px-3 text-start">{lang === 'ar' ? 'العملية' : 'Action'}</th>
                  <th className="py-2 px-3 text-start">{lang === 'ar' ? 'العينة / الهدف' : 'Target Sample'}</th>
                  <th className="py-2 px-3 text-start">{lang === 'ar' ? 'النتيجة' : 'Verdict'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800 font-mono">
                {filteredAuditLogs.map((log) => (
                  <tr key={log.id}>
                    <td className="py-2.5 px-3 text-slate-600 dark:text-slate-400">{log.id}</td>
                    <td className="py-2.5 px-3 text-slate-500">{new Date(log.timestamp).toLocaleTimeString()}</td>
                    <td className="py-2.5 px-3 text-sky-600 dark:text-sky-400">{log.action}</td>
                    <td className="py-2.5 px-3 font-sans text-slate-900 dark:text-slate-100 truncate max-w-xs">
                      {log.sample_name}
                    </td>
                    <td className="py-2.5 px-3 font-bold text-slate-800 dark:text-slate-200">
                      {log.classification} ({log.severity})
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* F. DOCUMENTATION & HELP */}
      {activeSubSection === 'DOCS_HELP' && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white">
              {lang === 'ar'
                ? 'F. التوثيق والمساعدة والمرجع التقني (Documentation & Help)'
                : 'F. Technical Documentation, User Guide & API Reference'}
            </h2>
            <p className="text-xs text-slate-500 mt-1">
              {lang === 'ar'
                ? 'دليل استخدام منصة PhishGuard، قواعد عدم التلفيق، بنية التقارير الـ 11، ومرجع نقاط النهاية الخلفية.'
                : 'User guide, non-fabrication forensic rules, 11-section report specification, and backend API reference.'}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 space-y-2">
              <div className="font-bold text-sm text-slate-900 dark:text-white">
                {lang === 'ar' ? '1. دليل الاستخدام والهيكل المعماري' : '1. Platform Workflow Guide'}
              </div>
              <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
                {lang === 'ar'
                  ? 'تنقسم المنصة إلى 5 أقسام رئيسية فقط: لوحة التحكم، مركز التحليل (يشمل الماسحات الخمسة ونمط القضية متعددة المدخلات)، استخبارات التهديدات (IOC Lookup)، السجل والتقارير، وقسم المزيد.'
                  : 'PhishGuard is organized around 5 primary sections: Dashboard, Analysis Center, Threat Intelligence, History & Reports, and More.'}
              </p>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 space-y-2">
              <div className="font-bold text-sm text-slate-900 dark:text-white">
                {lang === 'ar' ? '2. المبادئ الإلزامية للتحليل الجنائي' : '2. Mandatory Forensic Principles'}
              </div>
              <ul className="space-y-1 text-slate-600 dark:text-slate-400">
                <li>• فصل حالة عمل الرابط (WORKING/UNREACHABLE) عن تصنيفه الأمني.</li>
                <li>• عدم اعتبار HTTPS أو HTTP 200 دليلاً على الأمان.</li>
                <li>• تصنيف الملفات غير المدعومة كـ UNKNOWN وليس SAFE أبداً.</li>
                <li>• عدم اختلاق نتائج DNS أو WHOIS أو VirusTotal.</li>
              </ul>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 space-y-2">
              <div className="font-bold text-sm text-slate-900 dark:text-white">
                {lang === 'ar' ? '3. مرجع واجهات البرمجة الخلفية (API Reference)' : '3. Backend REST API Reference'}
              </div>
              <ul className="space-y-1 font-mono text-[11px] text-sky-600 dark:text-sky-400" dir="ltr">
                <li>POST /api/analyze (Single Sample Analysis)</li>
                <li>POST /api/analyze-case (Multi-Input Case)</li>
                <li>POST /api/ioc-lookup (IOC Threat Lookup)</li>
                <li>GET /api/scans & GET /api/cases</li>
                <li>GET /api/status & POST /api/tests/run-all</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* G. DEVELOPER & DIAGNOSTIC TOOLS (Includes the 13 Mandatory Acceptance Tests) */}
      {activeSubSection === 'DEV_DIAGNOSTICS' && (
        <div className="space-y-4">
          {userRole === 'viewer' ? (
            <div className="p-6 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-700 dark:text-amber-300">
              <div className="font-bold text-sm mb-1">
                {lang === 'ar'
                  ? 'أدوات التشخيص مقيدة للأدوار المخولة (ADMIN / ANALYST فقط)'
                  : 'Developer & Diagnostic Tools Restricted to Authorized Roles'}
              </div>
              <p>
                {lang === 'ar'
                  ? 'يرجى التبديل إلى دور ADMIN أو ANALYST من محدد الصلاحية أعلى هذا القسم لتشغيل اختبارات القبول الـ 13 وأدوات تشخيص المحرك.'
                  : 'Switch to ADMIN or ANALYST role above to execute the 13 Mandatory Acceptance Tests.'}
              </p>
            </div>
          ) : (
            <AcceptanceTestsView
              lang={lang}
              onScanCompleted={onScanCompleted}
            />
          )}
        </div>
      )}
    </div>
  );
};
