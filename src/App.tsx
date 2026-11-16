import React, { useEffect, useState } from 'react';
import {
  Activity,
  BookOpen,
  ChevronDown,
  ChevronUp,
  Database,
  History,
  Languages,
  LayoutDashboard,
  Menu,
  Moon,
  MoreHorizontal,
  Plug,
  Radar,
  ScanSearch,
  Search,
  Shield,
  Sliders,
  Sun,
  Terminal,
  Users,
  X,
} from 'lucide-react';
import { DashboardView } from './components/DashboardView';
import {
  HistoryAndReportsView,
  ThreatIntelView,
} from './components/HistoryAndIntelViews';
import { MoreSectionView } from './components/MoreSectionView';
import { ScannerWorkspace } from './components/ScannerWorkspace';
import {
  User,
  auth,
  deleteScanReportFromFirestore,
  onAuthStateChanged,
  saveScanReportToFirestore,
  signInWithGoogle,
  signOutUser,
  subscribeUserScans,
} from './lib/firebase';
import {
  AnalysisCase,
  AnalysisMode,
  MoreSubSection,
  PhishGuardReport,
  PrimaryNavSection,
  ThreatIntelProviderStatus,
} from './types/phishguard';

/**
 * Single Source of Truth for the 5 Primary Navigation Sections (Section 3 & Section 6)
 */
const PRIMARY_NAV_SECTIONS: Array<{
  id: PrimaryNavSection;
  labelAr: string;
  labelEn: string;
  hash: string;
  Icon: React.ElementType;
  isSecondaryPriority?: boolean;
}> = [
  {
    id: 'DASHBOARD',
    labelAr: 'لوحة التحكم',
    labelEn: 'Dashboard',
    hash: '#/dashboard',
    Icon: LayoutDashboard,
  },
  {
    id: 'ANALYSIS_CENTER',
    labelAr: 'مركز التحليل',
    labelEn: 'Analysis Center',
    hash: '#/analysis',
    Icon: ScanSearch,
  },
  {
    id: 'THREAT_INTEL',
    labelAr: 'استخبارات التهديدات',
    labelEn: 'Threat Intelligence',
    hash: '#/threat-intel',
    Icon: Radar,
  },
  {
    id: 'HISTORY_REPORTS',
    labelAr: 'السجل والتقارير',
    labelEn: 'History & Reports',
    hash: '#/history-reports',
    Icon: History,
  },
  {
    id: 'MORE',
    labelAr: 'المزيد',
    labelEn: 'More',
    hash: '#/more/integrations',
    Icon: MoreHorizontal,
    isSecondaryPriority: true,
  },
];

const MORE_SUB_ITEMS: Array<{
  id: MoreSubSection;
  labelAr: string;
  labelEn: string;
  hash: string;
  Icon: React.ElementType;
}> = [
  { id: 'INTEGRATIONS', labelAr: 'التكاملات', labelEn: 'Integrations & Providers', hash: '#/more/integrations', Icon: Plug },
  { id: 'SYSTEM_HEALTH', labelAr: 'حالة النظام', labelEn: 'System Health', hash: '#/more/system-health', Icon: Activity },
  { id: 'SETTINGS_PRIVACY', labelAr: 'الإعدادات والخصوصية', labelEn: 'Settings & Privacy', hash: '#/more/settings', Icon: Sliders },
  { id: 'USER_ACCESS', labelAr: 'إدارة المستخدمين والصلاحيات', labelEn: 'User & Access Management', hash: '#/more/users', Icon: Users },
  { id: 'AUDIT_LOGS', labelAr: 'سجل التدقيق', labelEn: 'Audit Logs', hash: '#/more/audit-logs', Icon: Database },
  { id: 'DOCS_HELP', labelAr: 'التوثيق والمساعدة', labelEn: 'Documentation & Help', hash: '#/more/docs', Icon: BookOpen },
  { id: 'DEV_DIAGNOSTICS', labelAr: 'أدوات المطور والتشخيص', labelEn: 'Developer & Diagnostic Tools', hash: '#/more/diagnostics', Icon: Terminal },
];

export default function App() {
  const [activeSection, setActiveSection] = useState<PrimaryNavSection>('DASHBOARD');
  const [activeScannerMode, setActiveScannerMode] = useState<AnalysisMode>('URL');
  const [activeMoreSub, setActiveMoreSub] = useState<MoreSubSection>('INTEGRATIONS');
  const [moreMenuExpanded, setMoreMenuExpanded] = useState(false);

  const [selectedReportForScanner, setSelectedReportForScanner] = useState<PhishGuardReport | null>(null);
  const [selectedCaseForScanner, setSelectedCaseForScanner] = useState<AnalysisCase | null>(null);
  const [globalSearchQuery, setGlobalSearchQuery] = useState('');
  const [historyInitialQuery, setHistoryInitialQuery] = useState('');

  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [lang, setLang] = useState<'ar' | 'en'>('ar');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [userRole, setUserRole] = useState<'admin' | 'analyst' | 'viewer'>('admin');

  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  const [serverScans, setServerScans] = useState<PhishGuardReport[]>([]);
  const [firestoreScans, setFirestoreScans] = useState<PhishGuardReport[]>([]);
  const [serverCases, setServerCases] = useState<AnalysisCase[]>([]);
  const [providers, setProviders] = useState<ThreatIntelProviderStatus[]>([]);
  const [auditLogs, setAuditLogs] = useState<
    Array<{
      id: string;
      timestamp: string;
      action: string;
      sample_type: string;
      sample_name: string;
      classification: string;
      severity: string;
    }>
  >([]);

  const [consentExternal, setConsentExternal] = useState(true);
  const [retentionDays, setRetentionDays] = useState(90);

  // Sync theme and RTL/LTR direction with <html> and <body>
  useEffect(() => {
    const htmlEl = document.documentElement;
    if (theme === 'dark') {
      htmlEl.classList.add('dark');
      document.body.className = 'bg-slate-950 text-slate-100 antialiased selection:bg-sky-500/30';
    } else {
      htmlEl.classList.remove('dark');
      document.body.className = 'bg-slate-50 text-slate-900 antialiased selection:bg-sky-500/20';
    }
  }, [theme]);

  useEffect(() => {
    const htmlEl = document.documentElement;
    htmlEl.lang = lang;
    htmlEl.dir = lang === 'ar' ? 'rtl' : 'ltr';
  }, [lang]);

  // Backward-compatible URL Hash Routing (Section 8)
  useEffect(() => {
    const applyHashRoute = () => {
      const hash = window.location.hash.toLowerCase();
      if (!hash || hash === '#/' || hash === '#/dashboard') {
        setActiveSection('DASHBOARD');
      } else if (hash.startsWith('#/analysis') || hash === '#/url-scanner') {
        setActiveSection('ANALYSIS_CENTER');
        setActiveScannerMode('URL');
      } else if (hash === '#/message-scanner') {
        setActiveSection('ANALYSIS_CENTER');
        setActiveScannerMode('MESSAGE');
      } else if (hash === '#/email-scanner') {
        setActiveSection('ANALYSIS_CENTER');
        setActiveScannerMode('EMAIL');
      } else if (hash === '#/file-scanner') {
        setActiveSection('ANALYSIS_CENTER');
        setActiveScannerMode('FILE');
      } else if (hash === '#/image-scanner' || hash === '#/qr-scanner') {
        setActiveSection('ANALYSIS_CENTER');
        setActiveScannerMode('IMAGE');
      } else if (hash === '#/threat-intel') {
        setActiveSection('THREAT_INTEL');
      } else if (hash === '#/history-reports' || hash === '#/history' || hash === '#/reports') {
        setActiveSection('HISTORY_REPORTS');
      } else if (hash.startsWith('#/more') || hash === '#/settings' || hash === '#/status') {
        setActiveSection('MORE');
        setMoreMenuExpanded(true);
        if (hash.includes('system-health') || hash === '#/status') {
          setActiveMoreSub('SYSTEM_HEALTH');
        } else if (hash.includes('settings')) {
          setActiveMoreSub('SETTINGS_PRIVACY');
        } else if (hash.includes('users')) {
          setActiveMoreSub('USER_ACCESS');
        } else if (hash.includes('audit')) {
          setActiveMoreSub('AUDIT_LOGS');
        } else if (hash.includes('docs')) {
          setActiveMoreSub('DOCS_HELP');
        } else if (hash.includes('diagnostics')) {
          setActiveMoreSub('DEV_DIAGNOSTICS');
        } else {
          setActiveMoreSub('INTEGRATIONS');
        }
      }
    };

    applyHashRoute();
    window.addEventListener('hashchange', applyHashRoute);
    return () => window.removeEventListener('hashchange', applyHashRoute);
  }, []);

  // Fetch initial real data from server
  const refreshServerState = async () => {
    try {
      const [scansRes, casesRes, statusRes] = await Promise.all([
        fetch('/api/scans'),
        fetch('/api/cases'),
        fetch('/api/status'),
      ]);
      if (scansRes.ok) {
        const scansData = await scansRes.json();
        setServerScans(scansData.scans || []);
      }
      if (casesRes.ok) {
        const casesData = await casesRes.json();
        setServerCases(casesData.cases || []);
      }
      if (statusRes.ok) {
        const statusData = await statusRes.json();
        setProviders(statusData.providers || []);
        setAuditLogs(statusData.auditLogs || []);
      }
    } catch {
      // Ignore transient load error
    }
  };

  useEffect(() => {
    refreshServerState();
  }, []);

  // Firebase Auth & Firestore listener
  useEffect(() => {
    let unsubScans: (() => void) | null = null;
    const unsubAuth = onAuthStateChanged(auth, (user) => {
      setCurrentUser(user);
      if (unsubScans) {
        unsubScans();
        unsubScans = null;
      }
      if (user && user.emailVerified) {
        unsubScans = subscribeUserScans(user.uid, (reports) => {
          setFirestoreScans(reports);
        });
      } else {
        setFirestoreScans([]);
      }
    });

    return () => {
      unsubAuth();
      if (unsubScans) unsubScans();
    };
  }, []);

  // Merge Firestore and Server scans deduplicated by analysis_id
  const combinedScans = React.useMemo(() => {
    const map = new Map<string, PhishGuardReport>();
    for (const s of [...firestoreScans, ...serverScans]) {
      if (!map.has(s.analysis_id)) {
        map.set(s.analysis_id, s);
      }
    }
    return Array.from(map.values()).sort((a, b) =>
      b.analyzed_at.localeCompare(a.analyzed_at)
    );
  }, [firestoreScans, serverScans]);

  const handleOpenScanner = (mode: AnalysisMode, reportToShow?: PhishGuardReport) => {
    setActiveScannerMode(mode);
    setSelectedReportForScanner(reportToShow || null);
    setSelectedCaseForScanner(null);
    setActiveSection('ANALYSIS_CENTER');
    setMobileMenuOpen(false);
  };

  const handleOpenCaseInWorkspace = (analysisCase: AnalysisCase) => {
    setActiveScannerMode('MULTI_INPUT_CASE');
    setSelectedCaseForScanner(analysisCase);
    setSelectedReportForScanner(analysisCase.samples[0] || null);
    setActiveSection('ANALYSIS_CENTER');
    setMobileMenuOpen(false);
  };

  const handleScanCompleted = async (report: PhishGuardReport) => {
    setServerScans((prev) => [report, ...prev.filter((r) => r.analysis_id !== report.analysis_id)]);
    if (currentUser && currentUser.emailVerified) {
      try {
        await saveScanReportToFirestore(report);
      } catch {
        // Handled by handleFirestoreError
      }
    }
    refreshServerState();
  };

  const handleCaseCompleted = (analysisCase: AnalysisCase) => {
    setServerCases((prev) => [analysisCase, ...prev.filter((c) => c.case_id !== analysisCase.case_id)]);
    refreshServerState();
  };

  const handleDeleteScan = async (analysisId: string) => {
    await fetch(`/api/scans/${encodeURIComponent(analysisId)}`, { method: 'DELETE' });
    setServerScans((prev) => prev.filter((r) => r.analysis_id !== analysisId));
    if (currentUser && currentUser.emailVerified) {
      try {
        await deleteScanReportFromFirestore(analysisId);
      } catch {
        // Ignore if not in user's Firestore collection
      }
    }
  };

  const handleAuthAction = async () => {
    setAuthError(null);
    if (currentUser) {
      await signOutUser();
      return;
    }
    try {
      await signInWithGoogle();
    } catch (err) {
      setAuthError(
        err instanceof Error
          ? err.message
          : lang === 'ar'
          ? 'تعذر تسجيل الدخول عبر Google'
          : 'Google Sign-In failed'
      );
    }
  };

  const handleGlobalSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setHistoryInitialQuery(globalSearchQuery.trim());
    setActiveSection('HISTORY_REPORTS');
  };

  const onlineProvidersCount = providers.filter((p) => p.configured).length;

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
      {/* Global Header (Section 7): Platform identity, Global Search, Compact System-Status indicator, Language selector, Theme selector, User menu. NO duplicate navigation links. */}
      <header className="flex items-center justify-between gap-4 px-4 sm:px-6 py-3 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 no-print">
        {/* 1. Platform Identity */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle Navigation"
            className="lg:hidden p-2 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-200"
          >
            {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>

          <a
            href="#/dashboard"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('DASHBOARD');
            }}
            className="flex items-center gap-2 text-lg font-bold tracking-tight text-slate-900 dark:text-white whitespace-nowrap shrink-0"
          >
            <Shield className="w-5 h-5 text-sky-500" />
            <span>PhishGuard</span>
          </a>
        </div>

        {/* 2. Global Search (URL, Domain, Filename, SHA-256) */}
        <form onSubmit={handleGlobalSearchSubmit} className="hidden md:flex flex-1 max-w-md relative">
          <Search className="w-4 h-4 text-slate-400 absolute top-2.5 start-3 pointer-events-none" />
          <input
            type="text"
            value={globalSearchQuery}
            onChange={(e) => setGlobalSearchQuery(e.target.value)}
            placeholder={
              lang === 'ar'
                ? 'بحث شامل في التقارير (URL، النطاق، الملف، SHA-256)...'
                : 'Global search (URL, domain, filename, SHA-256)...'
            }
            aria-label={lang === 'ar' ? 'بحث شامل' : 'Global search'}
            className="w-full ps-9 pe-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
          />
        </form>

        {/* 3. Compact System-Status Indicator + Language Selector + Theme Selector + User Menu */}
        <div className="flex items-center gap-2.5 shrink-0">
          {/* Compact System-Status Indicator */}
          <button
            type="button"
            onClick={() => {
              setActiveSection('MORE');
              setActiveMoreSub('SYSTEM_HEALTH');
              setMoreMenuExpanded(true);
            }}
            title={lang === 'ar' ? 'حالة النظام والمحركات' : 'System Health Status'}
            className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-xs font-mono text-slate-700 dark:text-slate-300 hover:border-sky-500/50 transition-colors"
          >
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span>
              {lang === 'ar'
                ? `النظام نشط (${onlineProvidersCount}/${providers.length || 8})`
                : `ONLINE (${onlineProvidersCount}/${providers.length || 8})`}
            </span>
          </button>

          {/* Language Selector */}
          <button
            type="button"
            onClick={() => setLang(lang === 'ar' ? 'en' : 'ar')}
            aria-label="Toggle Language"
            className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <Languages className="w-3.5 h-3.5" />
            <span>{lang === 'ar' ? 'EN' : 'عربي'}</span>
          </button>

          {/* Theme Selector */}
          <button
            type="button"
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            aria-label="Toggle Theme"
            className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
          </button>

          {/* User Menu */}
          <button
            type="button"
            onClick={handleAuthAction}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            {currentUser
              ? lang === 'ar'
                ? `خروج (${currentUser.displayName || 'محلل'})`
                : `Sign Out (${currentUser.displayName || 'Analyst'})`
              : lang === 'ar'
              ? 'تسجيل الدخول (Google)'
              : 'Sign In'}
          </button>
        </div>
      </header>

      {/* Main SOC Workspace Shell (Sidebar with Strictly 5 Primary Sections + Main Viewport) */}
      <div className="flex-1 flex">
        {/* Desktop Sidebar Navigation — Strictly 5 Primary Sections */}
        <aside className="hidden lg:flex w-64 shrink-0 flex-col justify-between border-e border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 no-print">
          <div className="space-y-6">
            {/* Core 4 Primary Task Sections */}
            <nav aria-label={lang === 'ar' ? 'التنقل الرئيسي' : 'Primary Navigation'} className="space-y-1.5">
              {PRIMARY_NAV_SECTIONS.filter((s) => !s.isSecondaryPriority).map((item) => {
                const ItemIcon = item.Icon;
                const isActive = activeSection === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveSection(item.id);
                    }}
                    className={`w-full flex items-center gap-3 px-3.5 py-2.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                      isActive
                        ? 'bg-sky-600 text-white shadow-xs'
                        : 'text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                  >
                    <ItemIcon className="w-4 h-4 shrink-0" />
                    <span className="truncate">{lang === 'ar' ? item.labelAr : item.labelEn}</span>
                  </button>
                );
              })}

              {/* 5th Item: Visually Secondary "المزيد | More" Section */}
              <div className="pt-4 mt-4 border-t border-slate-200 dark:border-slate-800">
                <button
                  type="button"
                  onClick={() => {
                    if (activeSection !== 'MORE') {
                      setActiveSection('MORE');
                      setMoreMenuExpanded(true);
                    } else {
                      setMoreMenuExpanded(!moreMenuExpanded);
                    }
                  }}
                  aria-expanded={moreMenuExpanded || activeSection === 'MORE'}
                  className={`w-full flex items-center justify-between gap-2 px-3.5 py-2 text-xs font-medium rounded-lg transition-colors ${
                    activeSection === 'MORE'
                      ? 'bg-slate-200/80 dark:bg-slate-800 text-slate-900 dark:text-white font-semibold'
                      : 'text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <MoreHorizontal className="w-4 h-4 shrink-0" />
                    <span>{lang === 'ar' ? 'المزيد (More)' : 'More'}</span>
                  </div>
                  {moreMenuExpanded || activeSection === 'MORE' ? (
                    <ChevronUp className="w-3.5 h-3.5" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5" />
                  )}
                </button>

                {(moreMenuExpanded || activeSection === 'MORE') && (
                  <div className="mt-1.5 ms-3 ps-3 border-s border-slate-200 dark:border-slate-800 space-y-1">
                    {MORE_SUB_ITEMS.map((sub) => {
                      const SubIcon = sub.Icon;
                      const isSubActive = activeSection === 'MORE' && activeMoreSub === sub.id;
                      return (
                        <button
                          key={sub.id}
                          type="button"
                          onClick={() => {
                            setActiveSection('MORE');
                            setActiveMoreSub(sub.id);
                          }}
                          className={`w-full flex items-center gap-2 px-2.5 py-1.5 text-[11px] rounded-md transition-colors ${
                            isSubActive
                              ? 'text-sky-600 dark:text-sky-400 font-bold bg-sky-500/10'
                              : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                          }`}
                        >
                          <SubIcon className="w-3.5 h-3.5 shrink-0" />
                          <span className="truncate">{lang === 'ar' ? sub.labelAr : sub.labelEn}</span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            </nav>
          </div>

          {/* Compact Footer Info */}
          <div className="pt-4 border-t border-slate-200 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400 space-y-1">
            <div className="font-mono font-semibold text-slate-700 dark:text-slate-300">
              PhishGuard SOC v2.4
            </div>
            <div>
              {lang === 'ar'
                ? 'تحليل جنائي قائم على الأدلة التقنية'
                : 'Evidence-Based Threat Analysis'}
            </div>
          </div>
        </aside>

        {/* Main Viewport */}
        <main className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full space-y-6">
          {/* Mobile Navigation Drawer (Strictly the same 5 Primary Sections) */}
          {mobileMenuOpen && (
            <div className="lg:hidden rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 space-y-2 no-print">
              <div className="grid grid-cols-2 gap-2">
                {PRIMARY_NAV_SECTIONS.map((item) => {
                  const ItemIcon = item.Icon;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setActiveSection(item.id);
                        if (item.id !== 'MORE') {
                          setMobileMenuOpen(false);
                        }
                      }}
                      className={`flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded-lg ${
                        activeSection === item.id
                          ? 'bg-sky-600 text-white'
                          : 'text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-950'
                      }`}
                    >
                      <ItemIcon className="w-4 h-4 shrink-0" />
                      <span className="truncate">{lang === 'ar' ? item.labelAr : item.labelEn}</span>
                    </button>
                  );
                })}
              </div>

              {activeSection === 'MORE' && (
                <div className="pt-2 border-t border-slate-200 dark:border-slate-800 grid grid-cols-2 gap-1.5">
                  {MORE_SUB_ITEMS.map((sub) => (
                    <button
                      key={sub.id}
                      type="button"
                      onClick={() => {
                        setActiveMoreSub(sub.id);
                        setMobileMenuOpen(false);
                      }}
                      className={`px-2.5 py-1.5 text-[11px] rounded text-start ${
                        activeMoreSub === sub.id
                          ? 'bg-sky-500/15 text-sky-500 font-bold'
                          : 'text-slate-500'
                      }`}
                    >
                      {lang === 'ar' ? sub.labelAr : sub.labelEn}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {authError && (
            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-300 text-xs">
              {authError}
            </div>
          )}

          {/* 1. DASHBOARD */}
          {activeSection === 'DASHBOARD' && (
            <DashboardView
              lang={lang}
              scans={combinedScans}
              providers={providers}
              onOpenScanner={(mode) => handleOpenScanner(mode)}
              onSelectReport={(report) => handleOpenScanner(report.sample_type, report)}
              onOpenHistoryReports={() => setActiveSection('HISTORY_REPORTS')}
            />
          )}

          {/* 2. ANALYSIS CENTER (Single Workspace with 5 Individual Scanners + Multi-Input Case Mode) */}
          {activeSection === 'ANALYSIS_CENTER' && (
            <ScannerWorkspace
              activeScanner={activeScannerMode}
              onSelectScanner={(mode) => setActiveScannerMode(mode)}
              lang={lang}
              consentExternal={consentExternal}
              onToggleConsentExternal={setConsentExternal}
              onScanCompleted={handleScanCompleted}
              onCaseCompleted={handleCaseCompleted}
              initialReport={selectedReportForScanner}
              initialCase={selectedCaseForScanner}
            />
          )}

          {/* 3. THREAT INTELLIGENCE (Interactive IOC Lookup + Feed Attribution) */}
          {activeSection === 'THREAT_INTEL' && (
            <ThreatIntelView
              lang={lang}
              providers={providers}
              scans={combinedScans}
              consentExternal={consentExternal}
              onOpenIntegrationsInMore={() => {
                setActiveSection('MORE');
                setActiveMoreSub('INTEGRATIONS');
                setMoreMenuExpanded(true);
              }}
            />
          )}

          {/* 4. HISTORY & REPORTS (Consolidated History, Multi-Input Cases, Samples, and Exportable Reports) */}
          {activeSection === 'HISTORY_REPORTS' && (
            <HistoryAndReportsView
              lang={lang}
              scans={combinedScans}
              cases={serverCases}
              initialSearchQuery={historyInitialQuery}
              onDeleteScan={handleDeleteScan}
              onReanalyzeSample={(report) => handleOpenScanner(report.sample_type, report)}
              onOpenCaseInWorkspace={handleOpenCaseInWorkspace}
            />
          )}

          {/* 5. MORE — المزيد (Secondary & Administrative Section with 7 Sub-Modules) */}
          {activeSection === 'MORE' && (
            <MoreSectionView
              lang={lang}
              activeSubSection={activeMoreSub}
              onSelectSubSection={setActiveMoreSub}
              providers={providers}
              consentExternal={consentExternal}
              onToggleConsentExternal={setConsentExternal}
              retentionDays={retentionDays}
              onChangeRetentionDays={setRetentionDays}
              theme={theme}
              onToggleTheme={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              onToggleLang={() => setLang(lang === 'ar' ? 'en' : 'ar')}
              userRole={userRole}
              onChangeRolePreview={setUserRole}
              userEmail={currentUser?.email || null}
              auditLogs={auditLogs}
              onScanCompleted={handleScanCompleted}
            />
          )}
        </main>
      </div>
    </div>
  );
}
