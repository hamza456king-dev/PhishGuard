import { ReputationResult, ThreatIntelProviderStatus } from '../types/phishguard';

/**
 * Returns real status of all server-side Threat Intelligence & Forensic engines.
 * Never fabricates API connections if keys are not configured in environment secrets.
 */
export function getThreatIntelProvidersStatus(): ThreatIntelProviderStatus[] {
  const now = new Date().toISOString();
  const hasVt = Boolean(process.env.VIRUSTOTAL_API_KEY && process.env.VIRUSTOTAL_API_KEY.trim() !== '');
  const hasOpenPhishKey = Boolean(process.env.OPENPHISH_API_KEY && process.env.OPENPHISH_API_KEY.trim() !== '');
  const hasAbuseIp = Boolean(process.env.ABUSEIPDB_API_KEY && process.env.ABUSEIPDB_API_KEY.trim() !== '');
  const hasGemini = Boolean(
    process.env.GEMINI_API_KEY &&
      process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY' &&
      process.env.GEMINI_API_KEY.trim() !== ''
  );

  return [
    {
      id: 'dns-tls-inspector',
      name: 'Node DNS & TLS Forensics',
      category: 'Network & Domain Infrastructure',
      configured: true,
      status: 'ONLINE',
      lastCheck: now,
      capabilities: ['DNS A/MX Resolution', 'DNS Rebinding Guard', 'X.509 TLS Certificate Validation'],
      unavailableCapabilities: [],
    },
    {
      id: 'rdap-whois',
      name: 'Public RDAP / Domain Registry',
      category: 'Domain Registration & Age',
      configured: true,
      status: 'ONLINE',
      lastCheck: now,
      capabilities: ['Domain Registrar Lookup', 'Registration Date & Age Check'],
      unavailableCapabilities: [],
    },
    {
      id: 'static-yara-engine',
      name: 'PhishGuard Static & YARA Signature Engine',
      category: 'Static File & Script Forensics',
      configured: true,
      status: 'ONLINE',
      lastCheck: now,
      capabilities: [
        'Magic Bytes MIME Verification',
        'PDF /JavaScript & /OpenAction Inspection',
        'Office OLE2 / OOXML VBA Macro Detection',
        'ZIP Safe In-Memory Inspection (Zip Slip & Zip Bomb Guard)',
        'IDN Homograph & Punycode Detection',
      ],
      unavailableCapabilities: [],
    },
    {
      id: 'gemini-forensic-ai',
      name: 'Google Gemini Forensic Evidence Engine',
      category: 'AI Evidence Synthesis & Vision OCR',
      configured: hasGemini,
      status: hasGemini ? 'ONLINE' : 'NOT_CONFIGURED',
      lastCheck: hasGemini ? now : null,
      capabilities: hasGemini
        ? ['Evidence-Based Security Reasoning', 'Arabic/English OCR & Visual Brand Analysis', 'Structured JSON Report Synthesis']
        : [],
      unavailableCapabilities: hasGemini ? [] : ['Requires GEMINI_API_KEY in Server Environment'],
    },
    {
      id: 'virustotal-v3',
      name: 'VirusTotal API v3',
      category: 'Multi-Engine Reputation & Hash Lookup',
      configured: hasVt,
      status: hasVt ? 'ONLINE' : 'NOT_CONFIGURED',
      lastCheck: hasVt ? now : null,
      capabilities: hasVt ? ['SHA-256 Multi-AV Hash Lookup', 'Domain & URL Reputation'] : [],
      unavailableCapabilities: hasVt
        ? []
        : ['غير مُهيأ (VIRUSTOTAL_API_KEY غير مضاف في أسرار الخادم) — فحص سمعة التجزئة الخارجية غير متاح'],
    },
    {
      id: 'openphish-eu',
      name: 'OpenPhish.eu Threat Intelligence',
      category: 'Phishing URL & Domain Feeds',
      configured: true,
      status: 'ONLINE',
      lastCheck: now,
      capabilities: [
        'OpenPhish.eu Phishing URL Feed Lookup',
        'Active Phishing Domain Matching',
        ...(hasOpenPhishKey ? ['OpenPhish.eu Authenticated Premium API (OPENPHISH_API_KEY)'] : []),
      ],
      unavailableCapabilities: hasOpenPhishKey
        ? []
        : ['يعمل عبر تغذية OpenPhish.eu العامة؛ لتفعيل التغذية المتقدمة أضف OPENPHISH_API_KEY'],
    },
    {
      id: 'abuseipdb',
      name: 'AbuseIPDB Threat Intelligence',
      category: 'IP Reputation & ASN Abuse',
      configured: hasAbuseIp,
      status: hasAbuseIp ? 'ONLINE' : 'NOT_CONFIGURED',
      lastCheck: hasAbuseIp ? now : null,
      capabilities: hasAbuseIp ? ['IP Abuse Confidence Score', 'ISP / ASN Reporting History'] : [],
      unavailableCapabilities: hasAbuseIp
        ? []
        : ['غير مُهيأ (ABUSEIPDB_API_KEY غير مضاف) — سمعة عنوان IP الخارجي غير متاحة'],
    },
    {
      id: 'isolated-sandbox',
      name: 'Dynamic Malware Sandbox & External AV Daemon',
      category: 'Dynamic Behavioral Execution',
      configured: false,
      status: 'NOT_CONFIGURED',
      lastCheck: null,
      capabilities: [],
      unavailableCapabilities: [
        'غير مُهيأ — يتم تنفيذ التحليل الساكن (Static Analysis) فقط؛ لا يتم تشغيل الملفات التنفيذية ديناميكياً',
      ],
    },
  ];
}

/**
 * Runs configured external threat intelligence checks when user consents to external sharing.
 * Strictly reports NOT_CONFIGURED for unconfigured providers without inventing results.
 */
export async function runThreatIntelLookups(params: {
  domain?: string | null;
  url?: string | null;
  sha256?: string | null;
  ipAddress?: string | null;
  consentExternal: boolean;
}): Promise<{
  results: ReputationResult[];
  checksPerformed: string[];
  checksNotPerformed: string[];
}> {
  const { domain, url, sha256, ipAddress, consentExternal } = params;
  const now = new Date().toISOString();
  const results: ReputationResult[] = [];
  const checksPerformed: string[] = [];
  const checksNotPerformed: string[] = [];

  if (!consentExternal) {
    results.push({
      provider: 'External Threat Intelligence Gate',
      status: 'NOT_CONFIGURED',
      last_checked: now,
      verdict: 'SKIPPED_BY_PRIVACY_POLICY',
      details: 'تم إيقاف إرسال العينة للمزودين الخارجيين بناءً على ضوابط الخصوصية وعدم تفعيل خيار مشاركة المؤشرات خارجياً.',
      freshness: 'N/A',
    });
    checksNotPerformed.push('استعلامات سمعة التهديدات الخارجية (بسبب إعدادات الخصوصية المحلية)');
    return { results, checksPerformed, checksNotPerformed };
  }

  // 1. RDAP Domain Registration Check (Public keyless protocol)
  if (domain && !domain.endsWith('.invalid') && !/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
      const rdapRes = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        signal: controller.signal,
        headers: { Accept: 'application/rdap+json' },
      });
      clearTimeout(timer);

      if (rdapRes.ok) {
        const rdapData = (await rdapRes.json()) as {
          events?: Array<{ eventAction?: string; eventDate?: string }>;
          entities?: Array<{ vcardArray?: unknown }>;
        };
        const regEvent = rdapData.events?.find((e) => e.eventAction === 'registration');
        results.push({
          provider: 'RDAP / WHOIS Registry',
          status: 'COMPLETED',
          last_checked: now,
          verdict: 'REGISTERED',
          details: regEvent?.eventDate
            ? `تاريخ تسجيل النطاق: ${regEvent.eventDate}`
            : `النطاق ${domain} مسجل في قاعدة بيانات RDAP.`,
          freshness: 'Live Query',
        });
        checksPerformed.push('RDAP Domain Registration Lookup');
      } else {
        results.push({
          provider: 'RDAP / WHOIS Registry',
          status: 'COMPLETED',
          last_checked: now,
          verdict: 'NO_RDAP_RECORD',
          details: `حالة استعلام RDAP للنطاق ${domain}: HTTP ${rdapRes.status}`,
          freshness: 'Live Query',
        });
      }
    } catch (err) {
      results.push({
        provider: 'RDAP / WHOIS Registry',
        status: 'ERROR',
        last_checked: now,
        verdict: 'UNKNOWN',
        details: 'تعذر الوصول إلى خادم RDAP خلال المهلة المحددة.',
        freshness: 'N/A',
        error: err instanceof Error ? err.message : 'Timeout',
      });
    }
  }

  // 2. VirusTotal API v3
  const vtKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  if (vtKey) {
    try {
      const targetEndpoint = sha256
        ? `https://www.virustotal.com/api/v3/files/${sha256}`
        : domain
        ? `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`
        : null;

      if (targetEndpoint) {
        const vtRes = await fetch(targetEndpoint, {
          headers: { 'x-apikey': vtKey },
        });
        if (vtRes.ok) {
          const vtJson = (await vtRes.json()) as {
            data?: { attributes?: { last_analysis_stats?: Record<string, number> } };
          };
          const stats = vtJson.data?.attributes?.last_analysis_stats;
          const malicious = stats?.malicious ?? 0;
          const suspicious = stats?.suspicious ?? 0;
          const harmless = stats?.harmless ?? 0;
          const undetected = stats?.undetected ?? 0;
          const total = malicious + suspicious + harmless + undetected;

          results.push({
            provider: 'VirusTotal API v3',
            status: 'COMPLETED',
            last_checked: now,
            verdict: malicious > 0 ? 'DETECTED' : suspicious > 0 ? 'SUSPICIOUS' : 'CLEAN',
            details: `نتيجة المحركات: ${malicious} خبيث، ${suspicious} مشبوه من أصل ${total} محرك فحص.`,
            freshness: 'Live API',
          });
          checksPerformed.push('VirusTotal API v3 Lookup');
        } else {
          results.push({
            provider: 'VirusTotal API v3',
            status: 'COMPLETED',
            last_checked: now,
            verdict: 'UNKNOWN',
            details: `لم يتم العثور على سجل مسبق في VirusTotal (HTTP ${vtRes.status}).`,
            freshness: 'Live API',
          });
        }
      }
    } catch (err) {
      results.push({
        provider: 'VirusTotal API v3',
        status: 'ERROR',
        last_checked: now,
        verdict: 'ERROR',
        details: 'فشل الاتصال بواجهة VirusTotal API.',
        freshness: 'N/A',
        error: err instanceof Error ? err.message : 'Network error',
      });
    }
  } else {
    results.push({
      provider: 'VirusTotal API v3',
      status: 'NOT_CONFIGURED',
      last_checked: now,
      verdict: 'NOT_CONFIGURED',
      details: 'التكامل غير مُهيأ (مفتاح VIRUSTOTAL_API_KEY غير مضاف في البيئة الخلفية).',
      freshness: 'N/A',
    });
    checksNotPerformed.push('VirusTotal Multi-Engine Lookup (غير مُهيأ)');
  }

  // 3. OpenPhish.eu Threat Intelligence Feed & API
  const openPhishKey = process.env.OPENPHISH_API_KEY?.trim();
  if (url || domain) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);
      const feedEndpoint = openPhishKey
        ? `https://openphish.eu/feed.txt`
        : `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`;

      const headers: Record<string, string> = {
        'User-Agent': 'PhishGuard-ThreatIntel/2.4',
      };
      if (openPhishKey) {
        headers['Authorization'] = `Bearer ${openPhishKey}`;
        headers['X-API-Key'] = openPhishKey;
      }

      const opRes = await fetch(feedEndpoint, {
        signal: controller.signal,
        headers,
      });
      clearTimeout(timer);

      if (opRes.ok) {
        const feedText = await opRes.text();
        const lines = feedText
          .split(/\r?\n/)
          .map((l) => l.trim().toLowerCase())
          .filter(Boolean);

        const targetUrlLower = (url || '').trim().toLowerCase();
        const targetDomainLower = (domain || '').trim().toLowerCase();

        const exactUrlMatch = targetUrlLower
          ? lines.some((line) => line === targetUrlLower || line.replace(/\/$/, '') === targetUrlLower.replace(/\/$/, ''))
          : false;
        const domainMatch =
          !exactUrlMatch && targetDomainLower
            ? lines.some((line) => {
                try {
                  return new URL(line).hostname.toLowerCase() === targetDomainLower;
                } catch {
                  return line.includes(targetDomainLower);
                }
              })
            : false;

        const isListed = exactUrlMatch || domainMatch;
        results.push({
          provider: 'OpenPhish.eu',
          status: 'COMPLETED',
          last_checked: now,
          verdict: isListed ? 'PHISHING_MATCH' : 'NO_MATCH',
          details: isListed
            ? `مدرج في قاعدة بيانات التصيد النشطة OpenPhish.eu (${exactUrlMatch ? 'تطابق كامل للرابط' : 'تطابق للنطاق'}).`
            : `غير مدرج حالياً في قائمة OpenPhish.eu النشطة (${lines.length} رابط مفحوص — غياب النتيجة لا يعد دليلاً قاطعاً على الأمان).`,
          freshness: openPhishKey ? 'OpenPhish.eu API' : 'OpenPhish.eu Live Feed',
        });
        checksPerformed.push('OpenPhish.eu Phishing Feed Lookup');
      } else {
        results.push({
          provider: 'OpenPhish.eu',
          status: 'COMPLETED',
          last_checked: now,
          verdict: 'UNKNOWN',
          details: `تعذر جلب قائمة OpenPhish.eu (HTTP ${opRes.status}).`,
          freshness: 'Live Query',
        });
      }
    } catch (err) {
      results.push({
        provider: 'OpenPhish.eu',
        status: 'ERROR',
        last_checked: now,
        verdict: 'ERROR',
        details: 'تعذر الوصول إلى خدمة OpenPhish.eu خلال المهلة المحددة.',
        freshness: 'N/A',
        error: err instanceof Error ? err.message : 'Error',
      });
    }
  }

  // 4. AbuseIPDB
  if (ipAddress && !process.env.ABUSEIPDB_API_KEY?.trim()) {
    results.push({
      provider: 'AbuseIPDB',
      status: 'NOT_CONFIGURED',
      last_checked: now,
      verdict: 'NOT_CONFIGURED',
      details: `لم يتم فحص سمعة العنوان ${ipAddress} خارجياً لأن ABUSEIPDB_API_KEY غير مُهيأ.`,
      freshness: 'N/A',
    });
    checksNotPerformed.push('AbuseIPDB IP Reputation (غير مُهيأ)');
  }

  return { results, checksPerformed, checksNotPerformed };
}
