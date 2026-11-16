import React, { useEffect, useState } from 'react';
import jsQR from 'jsqr';
import {
  AlertCircle,
  CheckCircle2,
  FileUp,
  FolderKanban,
  Globe,
  Image as ImageIcon,
  Loader2,
  Mail,
  MessageSquareWarning,
  Play,
  QrCode,
  Sparkles,
  Upload,
} from 'lucide-react';
import { MANDATORY_ACCEPTANCE_TESTS } from '../engine/acceptanceCases';
import {
  AcceptanceTestCase,
  AnalysisCase,
  AnalysisMode,
  PhishGuardReport,
} from '../types/phishguard';
import { ReportView } from './ReportView';

interface ScannerWorkspaceProps {
  activeScanner: AnalysisMode;
  onSelectScanner: (mode: AnalysisMode) => void;
  lang: 'ar' | 'en';
  consentExternal: boolean;
  onToggleConsentExternal: (val: boolean) => void;
  onScanCompleted: (report: PhishGuardReport) => void;
  onCaseCompleted?: (analysisCase: AnalysisCase) => void;
  initialReport?: PhishGuardReport | null;
  initialCase?: AnalysisCase | null;
}

export const ScannerWorkspace: React.FC<ScannerWorkspaceProps> = ({
  activeScanner,
  onSelectScanner,
  lang,
  consentExternal,
  onToggleConsentExternal,
  onScanCompleted,
  onCaseCompleted,
  initialReport,
  initialCase,
}) => {
  // Input states for each of the 5 scanners
  const [urlInput, setUrlInput] = useState('https://alrajh1-bank-verify-login.com/auth/signin');
  const [simulateRedirectTo, setSimulateRedirectTo] = useState('');
  const [simulateUnreachable, setSimulateUnreachable] = useState(false);

  const [messageInput, setMessageInput] = useState(
    MANDATORY_ACCEPTANCE_TESTS[5].payload.message || ''
  );

  const [emailInput, setEmailInput] = useState(
    MANDATORY_ACCEPTANCE_TESTS[7].payload.emailRaw || ''
  );

  const [fileName, setFileName] = useState(
    MANDATORY_ACCEPTANCE_TESTS[10].payload.fileName || 'shipment_documents.zip'
  );
  const [fileMimeType, setFileMimeType] = useState(
    MANDATORY_ACCEPTANCE_TESTS[10].payload.fileMimeType || 'application/zip'
  );
  const [fileBase64, setFileBase64] = useState(
    MANDATORY_ACCEPTANCE_TESTS[10].payload.fileContentBase64 || ''
  );

  const [imageName, setImageName] = useState(
    MANDATORY_ACCEPTANCE_TESTS[11].payload.fileName || 'qr_security_update_notice.png'
  );
  const [imageBase64, setImageBase64] = useState('');
  const [qrDecoded, setQrDecoded] = useState(
    MANDATORY_ACCEPTANCE_TESTS[11].payload.qrPayload || 'https://absh3r-gov-verify-login.com/otp-confirm'
  );
  const [imageDescription, setImageDescription] = useState(
    MANDATORY_ACCEPTANCE_TESTS[11].payload.imageDescription || ''
  );

  // Unified Multi-Input Case states
  const [caseName, setCaseName] = useState(
    'تحقيق مركّب: بريد تصيد مرفق بملف مضغوط ورابط مشبوه'
  );
  const [includeCaseEmail, setIncludeCaseEmail] = useState(true);
  const [includeCaseFile, setIncludeCaseFile] = useState(true);
  const [includeCaseUrl, setIncludeCaseUrl] = useState(true);
  const [includeCaseMessage, setIncludeCaseMessage] = useState(false);
  const [includeCaseImage, setIncludeCaseImage] = useState(false);

  const [useGemini, setUseGemini] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStageText, setScanStageText] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [currentReport, setCurrentReport] = useState<PhishGuardReport | null>(initialReport || null);
  const [currentCase, setCurrentCase] = useState<AnalysisCase | null>(initialCase || null);
  const [selectedCaseSampleIdx, setSelectedCaseSampleIdx] = useState(0);

  useEffect(() => {
    if (initialReport) {
      setCurrentReport(initialReport);
      setCurrentCase(null);
    }
  }, [initialReport]);

  useEffect(() => {
    if (initialCase) {
      setCurrentCase(initialCase);
      setSelectedCaseSampleIdx(0);
      if (initialCase.samples.length > 0) {
        setCurrentReport(initialCase.samples[0]);
      }
    }
  }, [initialCase]);

  const loadAcceptancePreset = (tc: AcceptanceTestCase) => {
    setErrorMsg(null);
    onSelectScanner(tc.sampleType);
    if (tc.sampleType === 'URL') {
      setUrlInput(tc.payload.url || '');
      setSimulateRedirectTo(tc.payload.simulateRedirectTo || '');
      setSimulateUnreachable(Boolean(tc.payload.simulateUnreachable));
    } else if (tc.sampleType === 'MESSAGE') {
      setMessageInput(tc.payload.message || '');
    } else if (tc.sampleType === 'EMAIL') {
      setEmailInput(tc.payload.emailRaw || '');
    } else if (tc.sampleType === 'FILE') {
      setFileName(tc.payload.fileName || 'sample.bin');
      setFileMimeType(tc.payload.fileMimeType || 'application/octet-stream');
      setFileBase64(tc.payload.fileContentBase64 || '');
    } else if (tc.sampleType === 'IMAGE') {
      setImageName(tc.payload.fileName || 'qr_sample.png');
      setQrDecoded(tc.payload.qrPayload || '');
      setImageDescription(tc.payload.imageDescription || '');
      setImageBase64('');
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
      setErrorMsg(lang === 'ar' ? 'حجم الملف يتجاوز الحد الأقصى المسموح (10 ميجابايت).' : 'File exceeds 10MB limit.');
      return;
    }
    setErrorMsg(null);
    setFileName(file.name);
    setFileMimeType(file.type || 'application/octet-stream');
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || '');
      const base64Part = result.includes(',') ? result.split(',')[1] : result;
      setFileBase64(base64Part);
    };
    reader.readAsDataURL(file);
  };

  const handleEmlFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setEmailInput(String(reader.result || ''));
    };
    reader.readAsText(file);
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 8 * 1024 * 1024) {
      setErrorMsg(lang === 'ar' ? 'حجم الصورة يتجاوز 8 ميجابايت.' : 'Image exceeds 8MB limit.');
      return;
    }
    setErrorMsg(null);
    setImageName(file.name);

    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result || '');
      const base64Part = dataUrl.includes(',') ? dataUrl.split(',')[1] : dataUrl;
      setImageBase64(base64Part);

      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        if (ctx) {
          ctx.drawImage(img, 0, 0);
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const qr = jsQR(imageData.data, imageData.width, imageData.height);
          if (qr && qr.data) {
            setQrDecoded(qr.data);
          }
        }
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  };

  const handleExecuteScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (activeScanner === 'MULTI_INPUT_CASE') {
      const inputs = [];
      if (includeCaseEmail && emailInput.trim()) {
        inputs.push({
          sampleType: 'EMAIL',
          sampleName: 'بريد إلكتروني ضمن القضية',
          emailRaw: emailInput,
        });
      }
      if (includeCaseFile && fileBase64) {
        inputs.push({
          sampleType: 'FILE',
          sampleName: fileName,
          fileName,
          fileMimeType,
          fileContentBase64: fileBase64,
        });
      }
      if (includeCaseUrl && urlInput.trim()) {
        inputs.push({
          sampleType: 'URL',
          sampleName: urlInput.trim(),
          url: urlInput.trim(),
          simulateRedirectTo: simulateRedirectTo.trim() || undefined,
          simulateUnreachable,
        });
      }
      if (includeCaseMessage && messageInput.trim()) {
        inputs.push({
          sampleType: 'MESSAGE',
          sampleName: 'رسالة نصية ضمن القضية',
          message: messageInput,
        });
      }
      if (includeCaseImage && (imageBase64 || qrDecoded.trim() || imageDescription.trim())) {
        inputs.push({
          sampleType: 'IMAGE',
          sampleName: imageName,
          fileName: imageName,
          fileContentBase64: imageBase64 || undefined,
          qrPayload: qrDecoded.trim() || undefined,
          imageDescription: imageDescription.trim() || undefined,
        });
      }

      if (inputs.length === 0) {
        setErrorMsg(
          lang === 'ar'
            ? 'يرجى تحديد عينة واحدة على الأقل وتعبئة بياناتها لتحليل القضية متعددة المدخلات.'
            : 'Please select and populate at least one artifact input for the multi-input case.'
        );
        return;
      }

      setIsScanning(true);
      setScanStageText(
        lang === 'ar'
          ? `جاري فحص ${inputs.length} عينات بصورة مستقلة وتجميع ملف القضية الجنائية...`
          : `Analyzing ${inputs.length} samples independently and compiling unified case...`
      );

      try {
        const res = await fetch('/api/analyze-case', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            caseName: caseName.trim() || 'قضية تحقيق متعددة المدخلات',
            inputs,
            consentExternal,
            useGeminiEnrichment: useGemini,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'فشل تحليل القضية متعددة المدخلات.');
        }
        const createdCase = data as AnalysisCase;
        setCurrentCase(createdCase);
        setSelectedCaseSampleIdx(0);
        if (createdCase.samples.length > 0) {
          setCurrentReport(createdCase.samples[0]);
        }
        if (onCaseCompleted) {
          onCaseCompleted(createdCase);
        }
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : 'حدث خطأ أثناء تحليل القضية.');
      } finally {
        setIsScanning(false);
        setScanStageText('');
      }
      return;
    }

    // Single scanner validation
    if (activeScanner === 'URL' && !urlInput.trim()) {
      setErrorMsg(lang === 'ar' ? 'يرجى إدخال رابط URL للتحليل.' : 'Please enter a URL to analyze.');
      return;
    }
    if (activeScanner === 'MESSAGE' && !messageInput.trim()) {
      setErrorMsg(lang === 'ar' ? 'يرجى لصق نص الرسالة للتحليل.' : 'Please enter message content to analyze.');
      return;
    }
    if (activeScanner === 'EMAIL' && !emailInput.trim()) {
      setErrorMsg(lang === 'ar' ? 'يرجى إدخال ترويسات أو محتوى البريد الإلكتروني.' : 'Please provide email headers/body.');
      return;
    }
    if (activeScanner === 'FILE' && !fileBase64) {
      setErrorMsg(lang === 'ar' ? 'يرجى اختيار ملف أو نموذج اختبار لفحصه.' : 'Please upload a file or select a preset.');
      return;
    }
    if (activeScanner === 'IMAGE' && !imageBase64 && !qrDecoded.trim() && !imageDescription.trim()) {
      setErrorMsg(
        lang === 'ar'
          ? 'يرجى رفع صورة أو إدخال بيانات رمز QR المستخرج للفحص.'
          : 'Please upload an image or provide QR payload.'
      );
      return;
    }

    setIsScanning(true);
    setScanStageText(
      lang === 'ar'
        ? 'جاري التحقق من المدخلات واستخراج المؤشرات وإجراء الفحص الساكن والشبكي المعزول...'
        : 'Validating sample, extracting indicators, and running isolated forensic checks...'
    );

    try {
      const payload = {
        sampleType: activeScanner,
        url: activeScanner === 'URL' ? urlInput.trim() : undefined,
        simulateRedirectTo: activeScanner === 'URL' && simulateRedirectTo.trim() ? simulateRedirectTo.trim() : undefined,
        simulateUnreachable: activeScanner === 'URL' ? simulateUnreachable : undefined,
        message: activeScanner === 'MESSAGE' ? messageInput : undefined,
        emailRaw: activeScanner === 'EMAIL' ? emailInput : undefined,
        fileName: activeScanner === 'FILE' ? fileName : activeScanner === 'IMAGE' ? imageName : undefined,
        fileMimeType: activeScanner === 'FILE' ? fileMimeType : undefined,
        fileContentBase64:
          activeScanner === 'FILE' ? fileBase64 : activeScanner === 'IMAGE' && imageBase64 ? imageBase64 : undefined,
        qrPayload: activeScanner === 'IMAGE' ? qrDecoded.trim() : undefined,
        imageDescription: activeScanner === 'IMAGE' ? imageDescription.trim() : undefined,
        consentExternal,
        useGeminiEnrichment: useGemini,
      };

      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'فشل الفحص الأمني.');
      }

      const report = data as PhishGuardReport;
      setCurrentCase(null);
      setCurrentReport(report);
      onScanCompleted(report);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'حدث خطأ أثناء الاتصال بمحرك الفحص.');
    } finally {
      setIsScanning(false);
      setScanStageText('');
    }
  };

  const scannerTabs: Array<{
    type: AnalysisMode;
    labelAr: string;
    labelEn: string;
    inputDescAr: string;
    outputDescAr: string;
    Icon: React.ElementType;
  }> = [
    {
      type: 'URL',
      labelAr: 'ماسح الروابط (URL)',
      labelEn: 'URL Scanner',
      inputDescAr: 'رابط موقع أو نطاق',
      outputDescAr: 'حالة الرابط وسمعة النطاق',
      Icon: Globe,
    },
    {
      type: 'MESSAGE',
      labelAr: 'ماسح الرسائل (SMS)',
      labelEn: 'Message Scanner',
      inputDescAr: 'رسالة نصية أو تواصل',
      outputDescAr: 'كشف التصيد والهندسة الاجتماعية',
      Icon: MessageSquareWarning,
    },
    {
      type: 'EMAIL',
      labelAr: 'ماسح البريد (Email)',
      labelEn: 'Email Scanner',
      inputDescAr: 'بريد إلكتروني أو EML',
      outputDescAr: 'فحص SPF/DKIM/DMARC والمرسل',
      Icon: Mail,
    },
    {
      type: 'FILE',
      labelAr: 'ماسح الملفات (File)',
      labelEn: 'File Scanner',
      inputDescAr: 'مستند، أرشيف، أو سكربت',
      outputDescAr: 'تحليل ساكن وMagic Bytes',
      Icon: FileUp,
    },
    {
      type: 'IMAGE',
      labelAr: 'ماسح الصور (QR/OCR)',
      labelEn: 'Image Scanner',
      inputDescAr: 'صورة أو رمز QR',
      outputDescAr: 'OCR وفك رموز QR والروابط',
      Icon: ImageIcon,
    },
    {
      type: 'MULTI_INPUT_CASE',
      labelAr: 'قضية متعددة المدخلات',
      labelEn: 'Multi-Input Case',
      inputDescAr: 'دمج بريد + مرفق + رابط + صورة',
      outputDescAr: 'حكم موحّد مع فصل أدلة كل عينة',
      Icon: FolderKanban,
    },
  ];

  const matchingPresets =
    activeScanner === 'MULTI_INPUT_CASE'
      ? MANDATORY_ACCEPTANCE_TESTS.slice(0, 6)
      : MANDATORY_ACCEPTANCE_TESTS.filter((tc) => tc.sampleType === activeScanner);

  return (
    <div className="space-y-6">
      {/* Unified Analysis Center Header & Internal Mode Selector */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-5">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">
              {lang === 'ar'
                ? 'مركز التحليل الجنائي الموحّد (Analysis Center)'
                : 'Unified Cybersecurity Analysis Center'}
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              {lang === 'ar'
                ? 'مساحة عمل واحدة لجميع عمليات الفحص: اختر فحص عينة منفردة (روابط، رسائل، بريد، ملفات، صور) أو أنشئ قضية متعددة المدخلات مع الحفاظ على استقلال أدلة كل عينة.'
                : 'Single workspace for all cybersecurity scans: analyze individual artifacts or run a unified multi-input case while preserving independent sample evidence.'}
            </p>
          </div>

          {/* Privacy & Gemini Controls */}
          <div className="flex flex-wrap items-center gap-4 text-xs">
            <label className="inline-flex items-center gap-2 cursor-pointer text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                checked={consentExternal}
                onChange={(e) => onToggleConsentExternal(e.target.checked)}
                className="rounded border-slate-300 dark:border-slate-700 text-sky-600 focus:ring-sky-500"
              />
              <span>
                {lang === 'ar'
                  ? 'موافقة الخصوصية: الاستعلام من مصادر التهديدات الخارجية (RDAP/VT)'
                  : 'Privacy Consent: Query External Threat Intel'}
              </span>
            </label>

            <label className="inline-flex items-center gap-2 cursor-pointer text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                checked={useGemini}
                onChange={(e) => setUseGemini(e.target.checked)}
                className="rounded border-slate-300 dark:border-slate-700 text-sky-600 focus:ring-sky-500"
              />
              <Sparkles className="w-3.5 h-3.5 text-sky-500" />
              <span>
                {lang === 'ar' ? 'إثراء التفسير عبر محرك Gemini الخلفي' : 'Enrich Explanation via Server Gemini'}
              </span>
            </label>
          </div>
        </div>

        {/* 6 Internal Mode Tabs (5 Individual Scanners + 1 Multi-Input Case Mode) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2.5" role="tablist">
          {scannerTabs.map((tab) => {
            const TabIcon = tab.Icon;
            const isSelected = activeScanner === tab.type;
            return (
              <button
                key={tab.type}
                type="button"
                role="tab"
                aria-selected={isSelected}
                onClick={() => {
                  onSelectScanner(tab.type);
                  setErrorMsg(null);
                }}
                className={`text-start p-3 rounded-lg border transition-colors ${
                  isSelected
                    ? 'bg-sky-600/10 border-sky-500 text-slate-900 dark:text-white'
                    : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-2 font-semibold text-xs sm:text-sm">
                  <TabIcon className={`w-4 h-4 shrink-0 ${isSelected ? 'text-sky-500' : 'text-slate-400'}`} />
                  <span className="truncate">{lang === 'ar' ? tab.labelAr : tab.labelEn}</span>
                </div>
                <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400 line-clamp-2">
                  {tab.inputDescAr} ← {tab.outputDescAr}
                </div>
              </button>
            );
          })}
        </div>

        {/* Quick-load Presets from the 13 Mandatory Acceptance Tests */}
        {activeScanner !== 'MULTI_INPUT_CASE' && (
          <div className="mt-5 pt-4 border-t border-slate-200 dark:border-slate-800 flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">
              {lang === 'ar' ? 'نماذج اختبار معيارية جاهزة:' : 'Standard Forensic Test Samples:'}
            </span>
            {matchingPresets.map((tc) => (
              <button
                key={tc.id}
                type="button"
                onClick={() => loadAcceptancePreset(tc)}
                className="px-2.5 py-1 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-950 text-slate-700 dark:text-slate-300 hover:border-sky-500/50 hover:text-sky-600 dark:hover:text-sky-400 transition-colors"
              >
                {lang === 'ar' ? tc.titleAr : tc.titleEn}
              </button>
            ))}
          </div>
        )}

        {/* Active Scanner Form */}
        <form onSubmit={handleExecuteScan} className="mt-5 space-y-4">
          {activeScanner === 'URL' && (
            <div className="space-y-3">
              <div>
                <label htmlFor="url-scanner-input" className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  {lang === 'ar'
                    ? 'أدخل الرابط المراد فحصه (URL / Domain / Shortened Link):'
                    : 'Enter Target URL or Domain:'}
                </label>
                <input
                  id="url-scanner-input"
                  type="text"
                  dir="ltr"
                  value={urlInput}
                  onChange={(e) => {
                    setUrlInput(e.target.value);
                    setSimulateRedirectTo('');
                    setSimulateUnreachable(false);
                  }}
                  placeholder="https://example.com/login"
                  className="w-full px-4 py-2.5 text-sm font-mono rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
                />
              </div>

              {(simulateRedirectTo || simulateUnreachable) && (
                <div className="text-xs text-amber-600 dark:text-amber-400 font-mono">
                  {simulateRedirectTo && `وضع اختبار سلسلة التوجيه مفعل -> ${simulateRedirectTo}`}
                  {simulateUnreachable && 'وضع اختبار نطاق غير قابل للوصول (UNREACHABLE) مفعل'}
                </div>
              )}
            </div>
          )}

          {activeScanner === 'MESSAGE' && (
            <div>
              <label htmlFor="message-scanner-input" className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                {lang === 'ar'
                  ? 'الصق نص الرسالة (SMS / WhatsApp / Telegram / منصات التواصل):'
                  : 'Paste SMS, WhatsApp, or Social Message Text:'}
              </label>
              <textarea
                id="message-scanner-input"
                rows={4}
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                placeholder={lang === 'ar' ? 'الصق نص الرسالة المشبوهة هنا...' : 'Paste suspicious message here...'}
                className="w-full px-4 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
              />
            </div>
          )}

          {activeScanner === 'EMAIL' && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label htmlFor="email-scanner-input" className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                  {lang === 'ar'
                    ? 'الصق ترويسات البريد الكاملة (Raw Email Headers & Body) أو ارفع ملف EML:'
                    : 'Paste Raw Email Headers & Body or Upload .EML File:'}
                </label>
                <label className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-700">
                  <Upload className="w-3.5 h-3.5" />
                  <span>{lang === 'ar' ? 'رفع ملف .EML' : 'Upload .EML'}</span>
                  <input type="file" accept=".eml,.txt,.msg" onChange={handleEmlFileUpload} className="hidden" />
                </label>
              </div>
              <textarea
                id="email-scanner-input"
                dir="ltr"
                rows={6}
                value={emailInput}
                onChange={(e) => setEmailInput(e.target.value)}
                className="w-full px-4 py-2.5 text-xs font-mono rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
              />
            </div>
          )}

          {activeScanner === 'FILE' && (
            <div className="space-y-3">
              <div className="p-5 rounded-xl border-2 border-dashed border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-center">
                <FileUp className="w-8 h-8 text-sky-500 mx-auto mb-2" />
                <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {lang === 'ar'
                    ? `الملف المحدد للفحص الساكن: ${fileName}`
                    : `Selected File for Static Inspection: ${fileName}`}
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  {lang === 'ar'
                    ? 'يدعم PDF, Office (DOC/DOCM/XLS/PPT), ZIP, EXE/DLL/ELF, APK, JS/PS1/SH/PY. يتم الفحص الساكن وحساب SHA-256 دون تشغيل الملف.'
                    : 'Supports PDF, Office, ZIP, Executables, Scripts. Static inspection only; files are never executed.'}
                </p>
                <label className="mt-3 inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-slate-900 dark:bg-slate-800 text-white cursor-pointer hover:bg-slate-800 dark:hover:bg-slate-700 transition-colors">
                  <Upload className="w-3.5 h-3.5" />
                  <span>{lang === 'ar' ? 'اختيار ملف من جهازك' : 'Choose File from Device'}</span>
                  <input type="file" onChange={handleFileUpload} className="hidden" />
                </label>
              </div>
            </div>
          )}

          {activeScanner === 'IMAGE' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl border-2 border-dashed border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 flex flex-col justify-center items-center text-center">
                <QrCode className="w-8 h-8 text-sky-500 mb-2" />
                <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {lang === 'ar' ? `الصورة المحددة: ${imageName}` : `Selected Image: ${imageName}`}
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  {lang === 'ar'
                    ? 'استخراج نصوص OCR وفك رموز الاستجابة السريعة QR وتحليل الروابط المضمّنة.'
                    : 'Extracts OCR text, decodes QR codes, and routes embedded URLs to the URL analyzer.'}
                </p>
                <label className="mt-3 inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-slate-900 dark:bg-slate-800 text-white cursor-pointer hover:bg-slate-800">
                  <Upload className="w-3.5 h-3.5" />
                  <span>{lang === 'ar' ? 'رفع صورة (PNG / JPEG)' : 'Upload Image'}</span>
                  <input type="file" accept="image/*" onChange={handleImageUpload} className="hidden" />
                </label>
              </div>

              <div className="space-y-3">
                <div>
                  <label htmlFor="qr-decoded-input" className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    {lang === 'ar'
                      ? 'الرابط أو النص المستخرج من رمز QR (يُملأ تلقائياً عند فك الرمز أو يدوياً للاختبار):'
                      : 'Decoded QR Code Payload / Embedded URL:'}
                  </label>
                  <input
                    id="qr-decoded-input"
                    type="text"
                    dir="ltr"
                    value={qrDecoded}
                    onChange={(e) => setQrDecoded(e.target.value)}
                    className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="image-ocr-input" className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    {lang === 'ar' ? 'النص الظاهر في الصورة (OCR / سياق الصورة):' : 'Visible OCR Text / Context:'}
                  </label>
                  <textarea
                    id="image-ocr-input"
                    rows={2}
                    value={imageDescription}
                    onChange={(e) => setImageDescription(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100"
                  />
                </div>
              </div>
            </div>
          )}

          {activeScanner === 'MULTI_INPUT_CASE' && (
            <div className="space-y-4 pt-2 border-t border-slate-200 dark:border-slate-800">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="case-name-input" className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    {lang === 'ar' ? 'عنوان القضية الجنائية (Case Title):' : 'Investigation Case Title:'}
                  </label>
                  <input
                    id="case-name-input"
                    type="text"
                    value={caseName}
                    onChange={(e) => setCaseName(e.target.value)}
                    className="w-full px-3.5 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100"
                  />
                </div>
                <div>
                  <span className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                    {lang === 'ar'
                      ? 'حدد المدخلات المراد فحصها معاً ضمن هذه القضية (مع حفظ تقرير مستقل لكل مدخل):'
                      : 'Select Artifacts to Analyze Together in This Case:'}
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {[
                      { id: 'email', labelAr: 'بريد إلكتروني', labelEn: 'Email', checked: includeCaseEmail, set: setIncludeCaseEmail },
                      { id: 'file', labelAr: 'مرفق / ملف', labelEn: 'File Attachment', checked: includeCaseFile, set: setIncludeCaseFile },
                      { id: 'url', labelAr: 'رابط URL', labelEn: 'URL Link', checked: includeCaseUrl, set: setIncludeCaseUrl },
                      { id: 'msg', labelAr: 'رسالة نصية', labelEn: 'SMS/Message', checked: includeCaseMessage, set: setIncludeCaseMessage },
                      { id: 'img', labelAr: 'صورة / QR', labelEn: 'Image / QR', checked: includeCaseImage, set: setIncludeCaseImage },
                    ].map((item) => (
                      <label
                        key={item.id}
                        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium cursor-pointer transition-colors ${
                          item.checked
                            ? 'bg-sky-600/10 border-sky-500 text-sky-700 dark:text-sky-300'
                            : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={item.checked}
                          onChange={(e) => item.set(e.target.checked)}
                          className="rounded border-slate-300 dark:border-slate-700 text-sky-600"
                        />
                        <span>{lang === 'ar' ? item.labelAr : item.labelEn}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {includeCaseEmail && (
                  <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/70">
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                      {lang === 'ar' ? '1. ترويسات ونص البريد الإلكتروني (Email Raw):' : '1. Email Headers & Body:'}
                    </label>
                    <textarea
                      dir="ltr"
                      rows={4}
                      value={emailInput}
                      onChange={(e) => setEmailInput(e.target.value)}
                      className="w-full px-3 py-2 text-xs font-mono rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900"
                    />
                  </div>
                )}

                {includeCaseFile && (
                  <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/70 flex flex-col justify-between">
                    <div>
                      <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                        {lang === 'ar' ? '2. المرفق أو الملف المشبوه (File Attachment):' : '2. File Attachment:'}
                      </div>
                      <div className="text-xs font-mono text-sky-600 dark:text-sky-400 truncate">
                        {fileName} ({fileMimeType})
                      </div>
                      <p className="text-[11px] text-slate-500 mt-1">
                        {lang === 'ar'
                          ? 'سيتم حساب SHA-256 وفحص التوقيع الثنائي دون خلط نتائجه مع البريد أو الرابط.'
                          : 'SHA-256 & static signature check runs independently.'}
                      </p>
                    </div>
                    <label className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded bg-slate-900 dark:bg-slate-800 text-white cursor-pointer w-fit">
                      <Upload className="w-3.5 h-3.5" />
                      <span>{lang === 'ar' ? 'تغيير الملف المرفق' : 'Change File'}</span>
                      <input type="file" onChange={handleFileUpload} className="hidden" />
                    </label>
                  </div>
                )}

                {includeCaseUrl && (
                  <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/70">
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                      {lang === 'ar' ? '3. الرابط المرتبط بالقضية (Target URL):' : '3. Associated URL:'}
                    </label>
                    <input
                      type="text"
                      dir="ltr"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      className="w-full px-3 py-2 text-xs font-mono rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900"
                    />
                  </div>
                )}

                {includeCaseMessage && (
                  <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/70">
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                      {lang === 'ar' ? '4. الرسالة النصية المرتبطة (SMS / Social Message):' : '4. Associated Message:'}
                    </label>
                    <textarea
                      rows={2}
                      value={messageInput}
                      onChange={(e) => setMessageInput(e.target.value)}
                      className="w-full px-3 py-2 text-xs rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900"
                    />
                  </div>
                )}

                {includeCaseImage && (
                  <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/70">
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                      {lang === 'ar' ? '5. الصورة أو رمز QR المرتبط (QR / Screenshot):' : '5. Associated Image / QR:'}
                    </label>
                    <input
                      type="text"
                      dir="ltr"
                      value={qrDecoded}
                      onChange={(e) => setQrDecoded(e.target.value)}
                      placeholder="QR Payload URL"
                      className="w-full px-3 py-1.5 text-xs font-mono rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900"
                    />
                  </div>
                )}
              </div>
            </div>
          )}

          {errorMsg && (
            <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-700 dark:text-red-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {isScanning ? (
                <span className="inline-flex items-center gap-2 text-sky-600 dark:text-sky-400 font-medium">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>{scanStageText}</span>
                </span>
              ) : (
                <span>
                  {lang === 'ar'
                    ? 'بيئة الفحص معزولة: تُحظر عناوين الشبكات الداخلية (SSRF) ولا يتم تشغيل أي ملفات مرفوعة.'
                    : 'Isolated environment: SSRF guard active and uploaded files are never executed.'}
                </span>
              )}
            </div>

            <button
              type="submit"
              disabled={isScanning}
              className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white transition-colors whitespace-nowrap shrink-0"
            >
              {isScanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              <span>
                {activeScanner === 'MULTI_INPUT_CASE'
                  ? lang === 'ar'
                    ? 'تحليل القضية متعددة المدخلات وإصدار التقرير الموحّد'
                    : 'Analyze Multi-Input Case'
                  : lang === 'ar'
                  ? 'بدء التحليل الجنائي وإصدار التقرير'
                  : 'Run Forensic Analysis'}
              </span>
            </button>
          </div>
        </form>
      </div>

      {/* Consolidated Multi-Input Case Banner + Sample Selector (when a Case was analyzed or opened) */}
      {currentCase && (
        <div className="rounded-xl border border-sky-500/40 bg-sky-500/5 p-5 space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <FolderKanban className="w-5 h-5 text-sky-500" />
                <span className="text-xs font-mono uppercase tracking-wider text-sky-600 dark:text-sky-400">
                  {currentCase.case_id} • {currentCase.sample_count}{' '}
                  {lang === 'ar' ? 'عينات مستقلة داخل القضية' : 'Independent Samples in Case'}
                </span>
              </div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100 mt-1">
                {currentCase.case_name}
              </h2>
              <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 leading-relaxed">
                {currentCase.consolidated_summary}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="px-3 py-1 rounded-md text-xs font-bold bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/30">
                {lang === 'ar' ? 'الحكم الكلي للقضية:' : 'Overall Case Verdict:'} {currentCase.overall_classification} (
                {currentCase.overall_severity})
              </span>
              <span className="px-3 py-1 rounded-md text-xs font-mono bg-slate-200 dark:bg-slate-800 text-slate-800 dark:text-slate-200">
                Confidence: {currentCase.overall_confidence}%
              </span>
            </div>
          </div>

          {/* Individual Sample Selector Tabs — Ensures each sample's technical findings remain strictly separated */}
          <div className="pt-3 border-t border-sky-500/20">
            <div className="text-xs font-semibold text-slate-600 dark:text-slate-400 mb-2">
              {lang === 'ar'
                ? 'اختر أي عينة داخل القضية لمراجعة تقريرها الجنائي المستقل وأدلتها التقنية دون خلط:'
                : 'Select any sample in this case to inspect its independent forensic report and technical evidence:'}
            </div>
            <div className="flex flex-wrap gap-2">
              {currentCase.samples.map((s, idx) => {
                const isSelected = idx === selectedCaseSampleIdx;
                return (
                  <button
                    key={s.analysis_id}
                    type="button"
                    onClick={() => {
                      setSelectedCaseSampleIdx(idx);
                      setCurrentReport(s);
                    }}
                    className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold border transition-colors ${
                      isSelected
                        ? 'bg-sky-600 text-white border-sky-600'
                        : 'bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-800 hover:border-sky-500/50'
                    }`}
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>
                      [{idx + 1}] {s.sample_type}: {s.sample_name.slice(0, 32)} ({s.classification})
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Rendered Forensic Report */}
      {currentReport && (
        <ReportView
          report={currentReport}
          lang={lang}
          onReanalyze={() => {
            const fakeEvent = { preventDefault: () => {} } as React.FormEvent;
            handleExecuteScan(fakeEvent);
          }}
        />
      )}
    </div>
  );
};
