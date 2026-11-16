import crypto from 'node:crypto';
import AdmZip from 'adm-zip';
import {
  DomainAnalysisDetails,
  EmailAuthenticationResult,
  FileAnalysisResult,
  ImageAnalysisDetails,
  LinkStatus,
  PhishGuardReport,
  ReputationResult,
  SampleType,
  SecurityClassification,
  SeverityLevel,
  TechnicalIndicator,
} from '../types/phishguard';

// Known legitimate brands and their canonical domains
const KNOWN_BRANDS: Record<string, string[]> = {
  paypal: ['paypal.com', 'paypal.me'],
  alrajhi: ['alrajhibank.com.sa'],
  alahli: ['alahli.com', 'snb.com.sa'],
  snb: ['snb.com.sa'],
  alinma: ['alinma.com'],
  riyadbank: ['riyadbank.com'],
  aramex: ['aramex.com'],
  spl: ['splonline.com.sa'],
  absher: ['absher.sa'],
  nafath: ['iam.gov.sa'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
  apple: ['apple.com', 'icloud.com'],
  google: ['google.com', 'gmail.com', 'accounts.google.com'],
  amazon: ['amazon.com', 'amazon.sa', 'amazon.ae'],
  meta: ['facebook.com', 'instagram.com', 'whatsapp.com'],
  binance: ['binance.com'],
  netflix: ['netflix.com'],
  dhl: ['dhl.com'],
  stc: ['stc.com.sa', 'mystc.com.sa'],
};

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'rb.gy',
  'cutt.ly',
  'short.link',
  'ow.ly',
  'rebrand.ly',
  'tiny.cc',
  'lnkd.in',
  's.id',
]);

// Visual homoglyph / lookalike patterns for common brand typosquatting
const BRAND_TYPOSQUAT_PATTERNS: Array<{ brand: string; regex: RegExp; canonical: string }> = [
  { brand: 'PayPal', regex: /paypa[l1iI|][-\w]*|p[a@]ypal/i, canonical: 'paypal.com' },
  { brand: 'Al Rajhi Bank (مصرف الراجحي)', regex: /a[l1iI]?rajh[i1l][-\w]*|rajh[i1]-?bank/i, canonical: 'alrajhibank.com.sa' },
  { brand: 'SNB / AlAhli (البنك الأهلي)', regex: /a[l1]ah[l1][i1][-\w]*|snb-?bank|snb-?verify/i, canonical: 'snb.com.sa' },
  { brand: 'Absher (أبشر)', regex: /absh[e3]r[-\w]*/i, canonical: 'absher.sa' },
  { brand: 'Microsoft', regex: /m[i1l]cr[o0]s[o0]ft|micros0ft|rnicrosoft/i, canonical: 'microsoft.com' },
  { brand: 'Apple', regex: /app[l1I]e[-\w]*|[i1]c[l1I]oud/i, canonical: 'apple.com' },
  { brand: 'Amazon', regex: /am[a@]z[o0]n|arnazon/i, canonical: 'amazon.com' },
  { brand: 'Google', regex: /g[o0]{2}g[l1I]e/i, canonical: 'google.com' },
  { brand: 'Aramex', regex: /aram[e3]x[-\w]*/i, canonical: 'aramex.com' },
  { brand: 'Netflix', regex: /n[e3]tf[l1I][i1]x|netfIix/i, canonical: 'netflix.com' },
];

// Non-ASCII characters often used in IDN homograph attacks (Cyrillic, Greek, etc.)
const HOMOGLYPH_CHAR_MAP: Record<string, string> = {
  'а': 'Cyrillic small a (U+0430)',
  'е': 'Cyrillic small ie (U+0435)',
  'о': 'Cyrillic small o (U+043E)',
  'р': 'Cyrillic small er (U+0440)',
  'с': 'Cyrillic small es (U+0441)',
  'у': 'Cyrillic small u (U+0443)',
  'х': 'Cyrillic small ha (U+0445)',
  'і': 'Cyrillic small Ukrainian i (U+0456)',
  'ј': 'Cyrillic small je (U+0458)',
  'ѕ': 'Cyrillic small dze (U+0455)',
  'α': 'Greek small alpha (U+03B1)',
  'ο': 'Greek small omicron (U+03BF)',
  'ρ': 'Greek small rho (U+03C1)',
  'ν': 'Greek small nu (U+03BD)',
};

/**
 * Validates whether an IP address or hostname is safe from SSRF (blocks loopback,
 * private RFC1918, link-local, cloud metadata, and reserved ranges).
 */
export function isPrivateOrReservedHost(host: string): { blocked: boolean; reason?: string } {
  const cleanHost = host.trim().toLowerCase().replace(/^\[|\]$/g, '');

  if (
    cleanHost === 'localhost' ||
    cleanHost.endsWith('.localhost') ||
    cleanHost.endsWith('.local') ||
    cleanHost.endsWith('.internal') ||
    cleanHost === 'metadata.google.internal' ||
    cleanHost === 'metadata'
  ) {
    return { blocked: true, reason: `محجوب أمنياً (SSRF Guard): النطاق المحلي أو الداخلي غير مسموح (${cleanHost})` };
  }

  // IPv6 loopback / link-local / unique-local
  if (cleanHost === '::1' || cleanHost === '0:0:0:0:0:0:0:1' || cleanHost.startsWith('fe80:') || cleanHost.startsWith('fc00:') || cleanHost.startsWith('fd00:')) {
    return { blocked: true, reason: `محجوب أمنياً (SSRF Guard): عنوان IPv6 داخلي أو استرجاعي (${cleanHost})` };
  }

  // IPv4 check
  const ipv4Match = cleanHost.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const octets = ipv4Match.slice(1, 5).map(Number);
    if (octets.some((o) => o < 0 || o > 255)) {
      return { blocked: true, reason: 'عنوان IPv4 غير صالح' };
    }
    const [a, b] = octets;
    if (a === 127) {
      return { blocked: true, reason: 'محجوب أمنياً (SSRF Guard): عنوان Loopback (127.0.0.0/8)' };
    }
    if (a === 10) {
      return { blocked: true, reason: 'محجوب أمنياً (SSRF Guard): شبكة خاصة RFC1918 (10.0.0.0/8)' };
    }
    if (a === 172 && b >= 16 && b <= 31) {
      return { blocked: true, reason: 'محجوب أمنياً (SSRF Guard): شبكة خاصة RFC1918 (172.16.0.0/12)' };
    }
    if (a === 192 && b === 168) {
      return { blocked: true, reason: 'محجوب أمنياً (SSRF Guard): شبكة خاصة RFC1918 (192.168.0.0/16)' };
    }
    if (a === 169 && b === 254) {
      return { blocked: true, reason: 'محجوب أمنياً (SSRF Guard): عنوان Link-Local / Cloud Metadata (169.254.0.0/16)' };
    }
    if (a === 0 || a >= 224) {
      return { blocked: true, reason: 'محجوب أمنياً (SSRF Guard): عنوان IP محجوز أو Multicast' };
    }
  }

  return { blocked: false };
}

/**
 * Extracts raw Unicode host before URL constructor punycode-encodes it.
 */
function extractRawHostFromUrlString(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  const match = trimmed.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^/@]+@)?([^/:?#]+)/);
  if (match && match[1]) {
    return match[1];
  }
  const fallback = trimmed.match(/^([^/:?#]+)/);
  return fallback ? fallback[1] : trimmed;
}

export interface UrlStructuralAnalysis {
  valid: boolean;
  normalizedUrl: string | null;
  ssrfBlocked: boolean;
  ssrfReason?: string;
  details: DomainAnalysisDetails;
  indicators: TechnicalIndicator[];
  threatTypes: string[];
}

/**
 * Stage A: Pure structural and lexical URL & Domain analyzer.
 */
export function analyzeUrlStructure(rawInputUrl: string): UrlStructuralAnalysis {
  const trimmed = rawInputUrl.trim();
  const indicators: TechnicalIndicator[] = [];
  const threatTypes = new Set<string>();

  const withProtocol = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  const rawHostBeforePunycode = extractRawHostFromUrlString(withProtocol);

  let parsed: URL;
  try {
    parsed = new URL(withProtocol);
  } catch {
    return {
      valid: false,
      normalizedUrl: null,
      ssrfBlocked: false,
      details: {
        domain: null,
        subdomain: null,
        tld: null,
        protocol: null,
        port: null,
        path: null,
        query_params: [],
        is_ip_host: false,
        has_userinfo: false,
        is_shortener: false,
        is_punycode: false,
        has_homoglyphs: false,
        homoglyph_details: [],
        impersonated_brand: null,
        redirect_chain: [],
        dns_records: [],
        ip_address: null,
        tls_status: 'غير متاح',
        http_status: null,
        page_title: null,
        has_login_form: false,
        has_otp_field: false,
        has_payment_form: false,
      },
      indicators: [
        {
          name: 'بنية رابط غير صالحة (Malformed URL)',
          evidence: `تعذر تحليل الرابط: ${trimmed.slice(0, 120)}`,
          source: 'URL Structural Analyzer',
          severity: 'LOW',
          verified: true,
          category: 'TOOL_RESULT',
        },
      ],
      threatTypes: [],
    };
  }

  const protocol = parsed.protocol.replace(':', '').toLowerCase();
  if (protocol !== 'http' && protocol !== 'https') {
    indicators.push({
      name: 'بروتوكول غير قياسي (Non-HTTP/HTTPS Scheme)',
      evidence: `تم استخدام البروتوكول ${protocol}:// بدلاً من HTTPS`,
      source: 'URL Structural Analyzer',
      severity: 'HIGH',
      verified: true,
      category: 'TOOL_RESULT',
    });
  }

  const hostname = parsed.hostname.toLowerCase();
  const ssrfCheck = isPrivateOrReservedHost(hostname);

  const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
  const parts = hostname.split('.');
  let registrableDomain = hostname;
  let subdomain: string | null = null;
  let tld: string | null = null;

  if (!isIpHost && parts.length >= 2) {
    // Handle multi-part TLDs like .com.sa, .gov.sa, .co.uk
    const lastTwo = parts.slice(-2).join('.');
    const isCompoundTld = /^(com|gov|org|net|edu|co)\.(sa|uk|ae|eg|jo|au)$/i.test(lastTwo);
    const domainPartsCount = isCompoundTld ? 3 : 2;
    if (parts.length >= domainPartsCount) {
      registrableDomain = parts.slice(-domainPartsCount).join('.');
      subdomain = parts.slice(0, parts.length - domainPartsCount).join('.') || null;
      tld = isCompoundTld ? lastTwo : parts[parts.length - 1];
    } else {
      tld = parts[parts.length - 1];
    }
  }

  // 1. Check HTTP (Unencrypted)
  if (protocol === 'http') {
    indicators.push({
      name: 'اتصال غير مشفر (Insecure HTTP Protocol)',
      evidence: 'الرابط يستخدم بروتوكول HTTP غير المشفر، مما يعرض البيانات المرسلة للاعتراض.',
      source: 'URL Structural Analyzer',
      severity: 'MEDIUM',
      verified: true,
      category: 'TOOL_RESULT',
    });
  }

  // 2. Check Userinfo (@ trick in URL)
  const hasUserinfo = Boolean(parsed.username || parsed.password);
  if (hasUserinfo) {
    indicators.push({
      name: 'خداع بيانات المستخدم في الرابط (Embedded Userinfo @ Trick)',
      evidence: `يحتوي الرابط على بيانات قبل رمز @ (${parsed.username}@${hostname}) لتمويه النطاق الفعلي.`,
      source: 'URL Structural Analyzer',
      severity: 'HIGH',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Phishing');
    threatTypes.add('Social Engineering');
  }

  // 3. Direct IP host check
  if (isIpHost && !ssrfCheck.blocked) {
    indicators.push({
      name: 'استخدام عنوان IP مباشر بدلاً من اسم نطاق (Direct IP Host)',
      evidence: `الرابط يوجه مباشرة إلى عنوان الرقمي ${hostname} دون نطاق مسجل، وهو سلوك شائع في خوادم التصيد المؤقتة والبرمجيات الخبيثة.`,
      source: 'URL Structural Analyzer',
      severity: 'HIGH',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Phishing');
  }

  // 4. Non-standard port
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    indicators.push({
      name: 'استخدام منفذ شبكة غير معتاد (Unusual Network Port)',
      evidence: `المنفذ المستخدم هو :${parsed.port}`,
      source: 'URL Structural Analyzer',
      severity: 'MEDIUM',
      verified: true,
      category: 'TOOL_RESULT',
    });
  }

  // 5. URL Shortener detection
  const isShortener = URL_SHORTENERS.has(registrableDomain);
  if (isShortener) {
    indicators.push({
      name: 'استخدام خدمة اختصار روابط (URL Shortener Detected)',
      evidence: `النطاق ${registrableDomain} هو خدمة اختصار روابط تخفي الوجهة النهائية عن المستخدم قبل النقر.`,
      source: 'URL Structural Analyzer',
      severity: 'MEDIUM',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Malicious Redirects');
  }

  // 6. Punycode / IDN & Homoglyph detection
  const isPunycode = hostname.includes('xn--');
  const homoglyphDetails: string[] = [];

  for (const ch of rawHostBeforePunycode) {
    if (HOMOGLYPH_CHAR_MAP[ch]) {
      homoglyphDetails.push(`الحرف "${ch}" (${HOMOGLYPH_CHAR_MAP[ch]})`);
    } else if (ch.charCodeAt(0) > 127) {
      homoglyphDetails.push(`حرف Unicode غير لاتيني "${ch}" (U+${ch.charCodeAt(0).toString(16).toUpperCase()})`);
    }
  }

  // Also detect Latin lookalike confusion (e.g., 'paypaI' with uppercase I or 'rn' for 'm', '0' for 'o', '1' for 'l')
  if (/paypaI|g00gle|m1crosoft|alrajh1|a1rajhi|absh3r|netfIix/i.test(rawHostBeforePunycode)) {
    homoglyphDetails.push(`تشابه بصري خادع (Visual Character Substitution) في النطاق: ${rawHostBeforePunycode}`);
  }

  const hasHomoglyphs = isPunycode || homoglyphDetails.length > 0;
  if (hasHomoglyphs) {
    indicators.push({
      name: 'هجوم الأحرف المتشابهة بصريًا (IDN Homograph / Punycode Attack)',
      evidence: `النطاق الظاهر (${rawHostBeforePunycode}) يترجم إلى (${hostname}). التفاصيل: ${
        homoglyphDetails.join('، ') || 'ترميز Punycode (xn--)'
      }`,
      source: 'IDN & Homoglyph Inspector',
      severity: 'CRITICAL',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Phishing');
    threatTypes.add('Brand Impersonation');
  }

  // 7. Brand Impersonation in Domain, Subdomain, or Path
  let impersonatedBrand: string | null = null;
  const fullHostAndPath = `${hostname}${parsed.pathname}`.toLowerCase();

  for (const pattern of BRAND_TYPOSQUAT_PATTERNS) {
    if (pattern.regex.test(rawHostBeforePunycode) || pattern.regex.test(fullHostAndPath)) {
      const canonicalList = Object.values(KNOWN_BRANDS).flat();
      const isOfficial =
        registrableDomain === pattern.canonical ||
        (KNOWN_BRANDS[pattern.brand.toLowerCase()] &&
          KNOWN_BRANDS[pattern.brand.toLowerCase()].includes(registrableDomain));

      if (!isOfficial) {
        impersonatedBrand = `${pattern.brand} (${pattern.canonical})`;
        indicators.push({
          name: 'انتحال علامة تجارية وتمويه النطاق (Brand Impersonation / Typosquatting)',
          evidence: `الرابط يحاكي العلامة التجارية "${pattern.brand}" بينما النطاق الفعلي المسجل هو "${registrableDomain}" وليس النطاق الرسمي "${pattern.canonical}".`,
          source: 'Brand Spoofing Engine',
          severity: 'CRITICAL',
          verified: true,
          category: 'TOOL_RESULT',
        });
        threatTypes.add('Phishing');
        threatTypes.add('Brand Impersonation');
        threatTypes.add('Credential Harvesting');
        break;
      }
    }
  }

  // Also check if a known brand name appears in subdomain or path while root domain is different
  if (!impersonatedBrand) {
    for (const [brandKey, officialDomains] of Object.entries(KNOWN_BRANDS)) {
      if (!officialDomains.includes(registrableDomain)) {
        const brandInSubdomain = subdomain && subdomain.toLowerCase().includes(brandKey);
        const brandInPath = parsed.pathname.toLowerCase().includes(brandKey);
        const brandInDomain = registrableDomain.includes(brandKey);
        if (brandInSubdomain || brandInPath || brandInDomain) {
          impersonatedBrand = `${brandKey.toUpperCase()} (${officialDomains[0]})`;
          indicators.push({
            name: 'استخدام اسم علامة تجارية معروفة خارج نطاقها الرسمي (Deceptive Brand Placement)',
            evidence: `ظهور اسم "${brandKey}" في ${
              brandInSubdomain ? `النطاق الفرعي (${subdomain})` : brandInDomain ? `النطاق (${registrableDomain})` : `المسار (${parsed.pathname})`
            } بينما النطاق الحقيقي هو "${registrableDomain}" (النطاق الرسمي: ${officialDomains.join(' أو ')}).`,
            source: 'Brand Spoofing Engine',
            severity: 'HIGH',
            verified: true,
            category: 'TOOL_RESULT',
          });
          threatTypes.add('Phishing');
          threatTypes.add('Brand Impersonation');
          break;
        }
      }
    }
  }

  // 8. Suspicious keywords in domain or path (login, verify, update, otp, secure, wallet)
  const phishingKeywordsMatch = fullHostAndPath.match(
    /\b(verify|verification|secure-login|signin|account-update|confirm-identity|otp|password-reset|banking|suspended|unlock|wallet-connect|auth-check)\b/i
  );
  const isKnownTrustedRoot = Object.values(KNOWN_BRANDS).flat().includes(registrableDomain);

  if (phishingKeywordsMatch && !isKnownTrustedRoot) {
    indicators.push({
      name: 'أنماط استدراج بيانات اعتماد في مسار أو اسم النطاق (Credential Lure Keywords)',
      evidence: `يحتوي الرابط على مصطلحات استدراج حساسة ("${phishingKeywordsMatch[0]}") على نطاق غير موثوق (${registrableDomain}).`,
      source: 'Lexical URL Heuristics',
      severity: impersonatedBrand || hasHomoglyphs ? 'HIGH' : 'MEDIUM',
      verified: true,
      category: 'HEURISTIC',
    });
    threatTypes.add('Credential Harvesting');
  }

  // 9. Open Redirect query parameters
  const queryParams: string[] = [];
  parsed.searchParams.forEach((val, key) => {
    queryParams.push(`${key}=${val}`);
    if (/^(redirect|redirect_uri|url|next|continue|return|returnTo|goto|dest|target)$/i.test(key) && /^(https?:\/\/|\/\/)/i.test(val)) {
      indicators.push({
        name: 'معامل إعادة توجيه خارجية (Open Redirect Parameter)',
        evidence: `المعامل "${key}" يوجه إلى رابط خارجي مضمّن: ${val.slice(0, 100)}`,
        source: 'URL Structural Analyzer',
        severity: 'HIGH',
        verified: true,
        category: 'TOOL_RESULT',
      });
      threatTypes.add('Malicious Redirects');
    }
  });

  // 10. Suspicious High-Risk TLD heuristic (Note: not sufficient alone to declare malicious, per Section 3)
  if (tld && /^(xyz|top|buzz|icu|click|loan|work|gq|tk|ml|cf|ga|zip|mov)$/i.test(tld)) {
    indicators.push({
      name: 'امتداد نطاق علوي يكثر استخدامه في حملات التصيد (High-Abuse TLD)',
      evidence: `النطاق يستخدم الامتداد .${tld} الذي يكثر استغلاله في النطاقات المؤقتة، مع ملاحظة أن الامتداد وحده لا يعد دليلاً قاطعاً دون قرائن إضافية.`,
      source: 'Domain Heuristics',
      severity: 'LOW',
      verified: true,
      category: 'HEURISTIC',
    });
  }

  return {
    valid: true,
    normalizedUrl: parsed.toString(),
    ssrfBlocked: ssrfCheck.blocked,
    ssrfReason: ssrfCheck.reason,
    details: {
      domain: registrableDomain,
      subdomain,
      tld,
      protocol,
      port: parsed.port || (protocol === 'https' ? '443' : '80'),
      path: parsed.pathname || '/',
      query_params: queryParams,
      is_ip_host: isIpHost,
      has_userinfo: hasUserinfo,
      is_shortener: isShortener,
      is_punycode: isPunycode,
      has_homoglyphs: hasHomoglyphs,
      homoglyph_details: homoglyphDetails,
      impersonated_brand: impersonatedBrand,
      redirect_chain: [parsed.toString()],
      dns_records: [],
      ip_address: isIpHost ? hostname : null,
      tls_status: protocol === 'https' ? 'يتطلب فحص اتصال' : 'غير مشفر (HTTP)',
      http_status: null,
      page_title: null,
      has_login_form: false,
      has_otp_field: false,
      has_payment_form: false,
    },
    indicators,
    threatTypes: Array.from(threatTypes),
  };
}

/**
 * Extracts all URLs from plain text or HTML messages.
 */
export function extractUrlsFromText(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s"'<>)\]]+|www\.[^\s"'<>)\]]+/gi;
  const matches = text.match(urlRegex) || [];
  return Array.from(new Set(matches.map((u) => u.replace(/[.,;!?]+$/, ''))));
}

export interface MessageAnalysisOutput {
  indicators: TechnicalIndicator[];
  threatTypes: string[];
  extractedUrls: string[];
  urlAnalyses: UrlStructuralAnalysis[];
  urgencyScore: 'LOW' | 'MEDIUM' | 'HIGH';
  summaryAr: string;
}

/**
 * Section 5: SMS, WhatsApp, Telegram & Social Media Message Analyzer
 */
export function analyzeMessageContent(messageText: string): MessageAnalysisOutput {
  const text = messageText.trim();
  const indicators: TechnicalIndicator[] = [];
  const threatTypes = new Set<string>();
  let urgencyScore: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';

  // 1. OTP / Verification Code / Password Request Detection
  const otpRegex = /(رمز التحقق|كود التفعيل|كود التحقق|الرقم السري المؤقت|رمز التفعيل|أرسل الرمز|مشاركة الرمز|\bOTP\b|verification code|security code|one-time password|pin code|كلمة المرور)/i;
  if (otpRegex.test(text)) {
    indicators.push({
      name: 'طلب رمز تحقق أو بيانات سرية (OTP / Credential Harvesting Request)',
      evidence: `تحتوي الرسالة على طلب صريح أو استدراج لمشاركة رمز التحقق (OTP) أو كلمة المرور ("${text.match(otpRegex)?.[0]}"). الجهات الرسمية والبنوك لا تطلب أبدًا تزويدها برمز OTP.`,
      source: 'Social Engineering & Message Analyzer',
      severity: 'CRITICAL',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Phishing');
    threatTypes.add('Smishing');
    threatTypes.add('Credential Harvesting');
    threatTypes.add('Social Engineering');
    urgencyScore = 'HIGH';
  }

  // 2. Account Suspension / Threat / Urgency / Psychological Pressure
  const urgencyRegex = /(إيقاف حسابك|تجميد حسابك|تعليق حسابك|حظر بطاقتك|خلال \d+ ساعة|فوراً|عاجل|تحذير نهائي|تفادي إيقاف|account suspended|urgent action required|immediately|within 24 hours|unauthorized login attempt)/i;
  if (urgencyRegex.test(text)) {
    indicators.push({
      name: 'الضغط النفسي والتهديد بإيقاف الحساب (Psychological Urgency & Coercion)',
      evidence: `تستخدم الرسالة أسلوب التخويف والاستعجال ("${text.match(urgencyRegex)?.[0]}") لدفع الضحية إلى التفاعل السريع قبل التفكير أو التحقق.`,
      source: 'Social Engineering & Message Analyzer',
      severity: 'HIGH',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Social Engineering');
    threatTypes.add('Phishing');
    urgencyScore = 'HIGH';
  }

  // 3. Financial Fraud / Wire Transfer / Payment / Customs Fee Request
  const financialRegex = /(تحويل مبلغ|سداد رسوم|رسوم التوصيل|رسوم جمركية|تحديث بيانات البطاقة|البطاقة البنكية|رقم الآيبان|\bIBAN\b|CVV|wire transfer|unpaid customs fee|delivery fee|update payment|ربحت جائزة|جائزة نقدية|عائد استثماري مضمون)/i;
  if (financialRegex.test(text)) {
    indicators.push({
      name: 'استدراج مالي أو طلب بيانات دفع (Financial Scam / Fake Payment Request)',
      evidence: `تتضمن الرسالة مؤشرات مطالبة مالية أو وعود بجوائز/استثمارات وهمية ("${text.match(financialRegex)?.[0]}").`,
      source: 'Social Engineering & Message Analyzer',
      severity: 'HIGH',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Fake Payment Requests');
    threatTypes.add('Social Engineering');
    if (urgencyScore === 'LOW') urgencyScore = 'MEDIUM';
  }

  // 4. Institution / Bank / Delivery Impersonation in Message
  const entityRegex = /(مصرف الراجحي|البنك الأهلي|بنك الرياض|مصرف الإنماء|أبشر|نفاذ|البريد السعودي|سبل|أرامكس|دي إتش إل|البنك المركزي|ساما|PayPal|Aramex|DHL|Microsoft|Apple)/i;
  if (entityRegex.test(text) && (otpRegex.test(text) || urgencyRegex.test(text) || financialRegex.test(text))) {
    indicators.push({
      name: 'ادعاء تمثيل مؤسسة رسمية أو مالية (Institutional / Brand Impersonation Claim)',
      evidence: `تدّعي الرسالة صدورها عن جهة معروفة ("${text.match(entityRegex)?.[0]}") مع اقترانها بطلبات حساسة أو تهديد بإيقاف الخدمة.`,
      source: 'Social Engineering & Message Analyzer',
      severity: 'HIGH',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Brand Impersonation');
    threatTypes.add('Identity Impersonation');
  }

  // 5. Secrecy or Off-Channel Migration
  const secrecyRegex = /(لا تخبر أحداً|بسرية تامة|تواصل معنا عبر واتساب|انتقل إلى تيليجرام|keep this confidential|contact on whatsapp|telegram)/i;
  if (secrecyRegex.test(text)) {
    indicators.push({
      name: 'طلب السرية أو نقل المحادثة لقناة غير رسمية (Secrecy / Off-Channel Lure)',
      evidence: `تتضمن الرسالة طلباً للسرية أو الانتقال إلى قناة تواصل خارجية ("${text.match(secrecyRegex)?.[0]}").`,
      source: 'Social Engineering & Message Analyzer',
      severity: 'MEDIUM',
      verified: true,
      category: 'HEURISTIC',
    });
    threatTypes.add('Social Engineering');
  }

  // 6. Extract and analyze embedded URLs
  const extractedUrls = extractUrlsFromText(text);
  const urlAnalyses: UrlStructuralAnalysis[] = [];

  for (const url of extractedUrls) {
    const urlRes = analyzeUrlStructure(url);
    urlAnalyses.push(urlRes);
    for (const ind of urlRes.indicators) {
      indicators.push({
        ...ind,
        name: `[رابط مضمّن في الرسالة] ${ind.name}`,
      });
    }
    urlRes.threatTypes.forEach((t) => threatTypes.add(t));
  }

  const summaryAr =
    indicators.length > 0
      ? `تم رصد ${indicators.length} مؤشر(ات) تقنية وسلوكية في الرسالة، ومستوى الاستعجال/الضغط النفسي: ${urgencyScore}.`
      : 'لم تُكتشف مؤشرات تصيد أو هندسة اجتماعية واضحة في نص الرسالة المفحوص.';

  return {
    indicators,
    threatTypes: Array.from(threatTypes),
    extractedUrls,
    urlAnalyses,
    urgencyScore,
    summaryAr,
  };
}

export interface EmailAnalysisOutput {
  auth: EmailAuthenticationResult;
  indicators: TechnicalIndicator[];
  threatTypes: string[];
  extractedUrls: string[];
  mismatchedLinks: Array<{ displayText: string; actualHref: string }>;
}

/**
 * Section 6: Email Content, Headers (SPF, DKIM, DMARC, From/Reply-To Alignment) & Link Analyzer
 */
export function analyzeEmailSample(rawEmailInput: string): EmailAnalysisOutput {
  const indicators: TechnicalIndicator[] = [];
  const threatTypes = new Set<string>();
  const alignmentNotes: string[] = [];

  // Split headers and body if raw EML format is provided
  const normalized = rawEmailInput.replace(/\r\n/g, '\n');
  const headerBodySplit = normalized.indexOf('\n\n');
  const headerPart = headerBodySplit !== -1 ? normalized.slice(0, headerBodySplit) : normalized;
  const bodyPart = headerBodySplit !== -1 ? normalized.slice(headerBodySplit + 2) : normalized;

  // Unfold multiline headers
  const unfoldedHeaders = headerPart.replace(/\n[ \t]+/g, ' ');
  const headerLines = unfoldedHeaders.split('\n');

  const getHeader = (name: string): string | null => {
    const prefix = `${name.toLowerCase()}:`;
    for (const line of headerLines) {
      if (line.toLowerCase().startsWith(prefix)) {
        return line.slice(prefix.length).trim();
      }
    }
    return null;
  };

  const fromRaw = getHeader('From');
  const replyToRaw = getHeader('Reply-To');
  const returnPathRaw = getHeader('Return-Path');
  const subject = getHeader('Subject');
  const authResults = getHeader('Authentication-Results') || '';
  const receivedSpf = getHeader('Received-SPF') || '';
  const origIp = getHeader('X-Originating-IP');

  const extractEmailAddress = (headerVal: string | null): string | null => {
    if (!headerVal) return null;
    const angleMatch = headerVal.match(/<([^>]+@[^>]+)>/);
    if (angleMatch) return angleMatch[1].trim().toLowerCase();
    const plainMatch = headerVal.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return plainMatch ? plainMatch[1].trim().toLowerCase() : null;
  };

  const extractDisplayName = (headerVal: string | null): string | null => {
    if (!headerVal) return null;
    const idx = headerVal.indexOf('<');
    if (idx > 0) {
      return headerVal.slice(0, idx).replace(/["']/g, '').trim() || null;
    }
    return null;
  };

  const fromAddress = extractEmailAddress(fromRaw);
  const fromDisplayName = extractDisplayName(fromRaw);
  const replyToAddress = extractEmailAddress(replyToRaw);
  const returnPathAddress = extractEmailAddress(returnPathRaw);

  const getDomainOfEmail = (email: string | null): string | null => {
    if (!email || !email.includes('@')) return null;
    return email.split('@')[1].toLowerCase().trim();
  };

  const fromDomain = getDomainOfEmail(fromAddress);
  const replyToDomain = getDomainOfEmail(replyToAddress);
  const returnPathDomain = getDomainOfEmail(returnPathAddress);

  // Parse SPF, DKIM, DMARC only if authentication headers exist
  let spf: EmailAuthenticationResult['spf'] = 'UNKNOWN';
  let dkim: EmailAuthenticationResult['dkim'] = 'UNKNOWN';
  let dmarc: EmailAuthenticationResult['dmarc'] = 'UNKNOWN';

  const combinedAuthText = `${authResults} ${receivedSpf}`.toLowerCase();

  if (combinedAuthText.trim().length > 0) {
    const spfMatch = combinedAuthText.match(/spf\s*=\s*(pass|fail|softfail|neutral|none)/i) ||
      receivedSpf.match(/^(pass|fail|softfail|neutral|none)\b/i);
    if (spfMatch) {
      spf = spfMatch[1].toUpperCase() as EmailAuthenticationResult['spf'];
    }

    const dkimMatch = combinedAuthText.match(/dkim\s*=\s*(pass|fail|none)/i);
    if (dkimMatch) {
      dkim = dkimMatch[1].toUpperCase() as EmailAuthenticationResult['dkim'];
    }

    const dmarcMatch = combinedAuthText.match(/dmarc\s*=\s*(pass|fail|none)/i);
    if (dmarcMatch) {
      dmarc = dmarcMatch[1].toUpperCase() as EmailAuthenticationResult['dmarc'];
    }
  }

  // Check authentication failures
  if (dmarc === 'FAIL') {
    indicators.push({
      name: 'فشل مصادقة DMARC (DMARC Authentication Failure)',
      evidence: `سجل الرأس Authentication-Results يثبت فشل سياسة DMARC (dmarc=fail) للنطاق المرسل (${fromDomain || 'غير محدد'})، مما يدل على انتحال عنوان المرسل (Email Spoofing).`,
      source: 'Email Header Forensics',
      severity: 'CRITICAL',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Phishing');
    threatTypes.add('Business Email Compromise (BEC)');
    threatTypes.add('Identity Impersonation');
    alignmentNotes.push('فشل مصادقة DMARC يؤكد عدم تطابق أو فشل تفويض الخادم المرسل باسم النطاق الظاهر.');
  }

  if (spf === 'FAIL' || spf === 'SOFTFAIL') {
    indicators.push({
      name: `فشل التحقق من خادم الإرسال SPF (${spf})`,
      evidence: `الخادم المرسل غير مصرح له بإرسال رسائل باسم النطاق (${fromDomain || 'غير محدد'}) وفق سجل SPF.`,
      source: 'Email Header Forensics',
      severity: spf === 'FAIL' ? 'HIGH' : 'MEDIUM',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Phishing');
  }

  if (dkim === 'FAIL') {
    indicators.push({
      name: 'فشل التوقيع الرقمي للرسالة (DKIM Signature Failure)',
      evidence: 'التوقيع الرقمي DKIM للرسالة غير صالح أو تم التلاعب بمحتوى الرسالة أثناء النقل.',
      source: 'Email Header Forensics',
      severity: 'HIGH',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Phishing');
  }

  // Check From vs Reply-To Mismatch
  if (fromAddress && replyToAddress && fromAddress !== replyToAddress) {
    const isDifferentDomain = fromDomain !== replyToDomain;
    indicators.push({
      name: 'اختلاف عنوان المرسل From عن عنوان الرد Reply-To (Reply-To Mismatch)',
      evidence: `المرسل الظاهر في From هو (${fromAddress}) بينما يتم توجيه الردود في Reply-To إلى عنوان مختلف (${replyToAddress})${
        isDifferentDomain ? ` على نطاق خارجي مختلف (${replyToDomain})` : ''
      }.`,
      source: 'Email Header Forensics',
      severity: isDifferentDomain ? 'HIGH' : 'MEDIUM',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Phishing');
    threatTypes.add('Business Email Compromise (BEC)');
    alignmentNotes.push(`عدم تطابق بين From (${fromAddress}) و Reply-To (${replyToAddress}).`);
  }

  // Check From vs Return-Path domain misalignment
  if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
    indicators.push({
      name: 'عدم محاذاة نطاق المرسل مع مسار الإرجاع (Return-Path Domain Misalignment)',
      evidence: `نطاق المرسل (${fromDomain}) يختلف عن نطاق Return-Path الفعلي (${returnPathDomain}).`,
      source: 'Email Header Forensics',
      severity: 'MEDIUM',
      verified: true,
      category: 'TOOL_RESULT',
    });
    alignmentNotes.push(`Return-Path (${returnPathDomain}) لا يطابق نطاق From (${fromDomain}).`);
  }

  // Check Display Name Spoofing (e.g. Display name contains a brand or different email while actual email is free/unrelated)
  if (fromDisplayName && fromDomain) {
    const embeddedEmailInDisplay = extractEmailAddress(fromDisplayName);
    if (embeddedEmailInDisplay && embeddedEmailInDisplay !== fromAddress) {
      indicators.push({
        name: 'تضمين عنوان بريد مزيف داخل الاسم الظاهر (Display Name Email Spoofing)',
        evidence: `الاسم الظاهر يعرض العنوان (${embeddedEmailInDisplay}) بينما البريد الفعلي المرسل هو (${fromAddress}).`,
        source: 'Email Header Forensics',
        severity: 'CRITICAL',
        verified: true,
        category: 'TOOL_RESULT',
      });
      threatTypes.add('Phishing');
      threatTypes.add('Business Email Compromise (BEC)');
    }
  }

  // Check HTML Anchor Display Text vs Actual Href Mismatch
  const mismatchedLinks: Array<{ displayText: string; actualHref: string }> = [];
  const anchorRegex = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
  let match: RegExpExecArray | null;
  while ((match = anchorRegex.exec(bodyPart)) !== null) {
    const href = match[1].trim();
    const innerText = match[2].replace(/<[^>]+>/g, '').trim();
    if (/^https?:\/\//i.test(innerText) && /^https?:\/\//i.test(href)) {
      try {
        const displayedHost = new URL(innerText).hostname.toLowerCase();
        const actualHost = new URL(href).hostname.toLowerCase();
        if (displayedHost !== actualHost) {
          mismatchedLinks.push({ displayText: innerText, actualHref: href });
          indicators.push({
            name: 'تضارب النص الظاهر للرابط مع الوجهة الحقيقية (Deceptive Anchor Text vs Href)',
            evidence: `النص الظاهر للمستخدم يعرض النطاق (${displayedHost}) بينما الرابط الفعلي يوجه إلى (${actualHost}).`,
            source: 'Email HTML Content Inspector',
            severity: 'CRITICAL',
            verified: true,
            category: 'TOOL_RESULT',
          });
          threatTypes.add('Phishing');
        }
      } catch {
        // Ignore malformed URLs inside anchor comparison
      }
    }
  }

  // Also run message & URL analysis on the email subject + body
  const msgAnalysis = analyzeMessageContent(`${subject || ''}\n${bodyPart}`);
  for (const ind of msgAnalysis.indicators) {
    indicators.push(ind);
  }
  msgAnalysis.threatTypes.forEach((t) => threatTypes.add(t));

  return {
    auth: {
      spf,
      dkim,
      dmarc,
      from_address: fromAddress,
      from_display_name: fromDisplayName,
      reply_to: replyToAddress,
      return_path: returnPathAddress,
      subject,
      sender_ip: origIp,
      alignment_notes: alignmentNotes,
    },
    indicators,
    threatTypes: Array.from(threatTypes),
    extractedUrls: msgAnalysis.extractedUrls,
    mismatchedLinks,
  };
}

export interface FileStaticAnalysisOutput {
  fileAnalysis: FileAnalysisResult;
  indicators: TechnicalIndicator[];
  threatTypes: string[];
  isSupported: boolean;
  unsupportedReason?: string;
}

const SUPPORTED_TEXT_EXTENSIONS = new Set([
  'txt', 'js', 'ts', 'html', 'htm', 'css', 'xml', 'json', 'svg',
  'ps1', 'bat', 'cmd', 'sh', 'py', 'vbs', 'eml', 'msg', 'csv',
]);

const SUPPORTED_DOC_EXTENSIONS = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'docm', 'xlsm', 'pptm',
]);

const SUPPORTED_ARCHIVE_EXTENSIONS = new Set(['zip']);

const SUPPORTED_BINARY_EXTENSIONS = new Set(['exe', 'dll', 'elf', 'apk', 'macho', 'so', 'dylib']);

/**
 * Detects real MIME type from binary Magic Bytes.
 */
export function detectMagicBytesMime(buffer: Buffer): { mime: string | null; description: string; hexPrefix: string } {
  const hexPrefix = buffer.subarray(0, 8).toString('hex').toUpperCase();
  if (buffer.length < 4) {
    return { mime: 'text/plain', description: 'Short Buffer / Text', hexPrefix };
  }

  // PDF: %PDF- (25 50 44 46 2D)
  if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
    return { mime: 'application/pdf', description: 'PDF Document (%PDF)', hexPrefix };
  }
  // ZIP / OOXML / APK: PK\x03\x04 (50 4B 03 04)
  if (buffer[0] === 0x50 && buffer[1] === 0x4B && buffer[2] === 0x03 && buffer[3] === 0x04) {
    return { mime: 'application/zip', description: 'ZIP Archive / OOXML / APK Container (PK..)', hexPrefix };
  }
  // OLE2 Compound Document (DOC, XLS, PPT, MSG): D0 CF 11 E0 A1 B1 1A E1
  if (buffer[0] === 0xD0 && buffer[1] === 0xCF && buffer[2] === 0x11 && buffer[3] === 0xE0) {
    return { mime: 'application/x-ole-storage', description: 'Microsoft OLE2 Compound Document', hexPrefix };
  }
  // Windows PE Executable (EXE/DLL): MZ (4D 5A)
  if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
    return { mime: 'application/x-msdownload', description: 'Windows Portable Executable (PE / MZ)', hexPrefix };
  }
  // Linux ELF: 7F 45 4C 46 (.ELF)
  if (buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
    return { mime: 'application/x-elf', description: 'Linux ELF Executable', hexPrefix };
  }
  // macOS Mach-O: FE ED FA CE / FE ED FA CF / CF FA ED FE / CE FA ED FE
  if (
    (buffer[0] === 0xFE && buffer[1] === 0xED && buffer[2] === 0xFA && (buffer[3] === 0xCE || buffer[3] === 0xCF)) ||
    ((buffer[0] === 0xCE || buffer[0] === 0xCF) && buffer[1] === 0xFA && buffer[2] === 0xED && buffer[3] === 0xFE)
  ) {
    return { mime: 'application/x-mach-binary', description: 'macOS Mach-O Binary', hexPrefix };
  }
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    return { mime: 'image/png', description: 'PNG Image', hexPrefix };
  }
  // JPEG: FF D8 FF
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return { mime: 'image/jpeg', description: 'JPEG Image', hexPrefix };
  }
  // GIF: GIF87a or GIF89a
  if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38) {
    return { mime: 'image/gif', description: 'GIF Image', hexPrefix };
  }
  // RAR: 52 61 72 21 1A 07
  if (buffer[0] === 0x52 && buffer[1] === 0x61 && buffer[2] === 0x72 && buffer[3] === 0x21) {
    return { mime: 'application/vnd.rar', description: 'RAR Archive', hexPrefix };
  }
  // 7z: 37 7A BC AF 27 1C
  if (buffer[0] === 0x37 && buffer[1] === 0x7A && buffer[2] === 0xBC && buffer[3] === 0xAF) {
    return { mime: 'application/x-7z-compressed', description: '7-Zip Archive', hexPrefix };
  }
  // GZIP: 1F 8B
  if (buffer[0] === 0x1F && buffer[1] === 0x8B) {
    return { mime: 'application/gzip', description: 'GZIP Archive', hexPrefix };
  }

  // Check if mostly printable UTF-8/ASCII text
  const sampleSlice = buffer.subarray(0, Math.min(buffer.length, 512));
  let nonPrintable = 0;
  for (let i = 0; i < sampleSlice.length; i++) {
    const byte = sampleSlice[i];
    if (byte === 0) {
      nonPrintable += 20; // Null byte strongly indicates binary
      break;
    }
    if (byte < 9 || (byte > 13 && byte < 32)) {
      nonPrintable++;
    }
  }
  if (nonPrintable === 0) {
    return { mime: 'text/plain', description: 'UTF-8 / ASCII Text Content', hexPrefix };
  }

  return { mime: null, description: 'Unknown Binary Format', hexPrefix };
}

/**
 * Section 7: Modular File & Archive Static Security Analyzer
 */
export function analyzeFileBuffer(
  fileName: string,
  buffer: Buffer,
  declaredMimeType?: string
): FileStaticAnalysisOutput {
  const indicators: TechnicalIndicator[] = [];
  const threatTypes = new Set<string>();

  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
  const md5 = crypto.createHash('md5').update(buffer).digest('hex');

  const cleanName = fileName.trim();
  const nameParts = cleanName.split('.');
  const extension = nameParts.length > 1 ? nameParts[nameParts.length - 1].toLowerCase() : '';

  // Double extension check (e.g., invoice.pdf.exe or statement.docx.js)
  if (nameParts.length >= 3) {
    const secondLastExt = nameParts[nameParts.length - 2].toLowerCase();
    const dangerousFinalExts = new Set(['exe', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'hta', 'com', 'pif', 'apk']);
    if (
      ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'png', 'txt'].includes(secondLastExt) &&
      dangerousFinalExts.has(extension)
    ) {
      indicators.push({
        name: 'امتداد ملف مزدوج خادع (Deceptive Double Extension)',
        evidence: `اسم الملف "${cleanName}" يستخدم امتداداً مزدوجاً (.${secondLastExt}.${extension}) لإيهام المستخدم بأنه مستند عادي بينما هو ملف قابل للتنفيذ.`,
        source: 'File Static Analyzer',
        severity: 'CRITICAL',
        verified: true,
        category: 'TOOL_RESULT',
      });
      threatTypes.add('Malware Delivery');
      threatTypes.add('Social Engineering');
    }
  }

  const magic = detectMagicBytesMime(buffer);
  let detectedMime = magic.mime;

  // Refine OOXML (docx, xlsx, pptx) or APK when magic bytes are PK.. (application/zip)
  if (detectedMime === 'application/zip') {
    if (['docx', 'docm'].includes(extension)) detectedMime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    else if (['xlsx', 'xlsm'].includes(extension)) detectedMime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    else if (['pptx', 'pptm'].includes(extension)) detectedMime = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
    else if (extension === 'apk') detectedMime = 'application/vnd.android.package-archive';
  }

  // Detect extension vs true binary signature mismatch
  let extensionMismatch = false;
  if (
    magic.mime === 'application/x-msdownload' &&
    !['exe', 'dll', 'sys', 'scr'].includes(extension)
  ) {
    extensionMismatch = true;
    indicators.push({
      name: 'تضارب التوقيع الثنائي للملف مع امتداده (Executable Masquerading / MIME Spoofing)',
      evidence: `امتداد الملف الظاهر هو (.${extension || 'بدون امتداد'}) ولكن التوقيع الثنائي (Magic Bytes: ${magic.hexPrefix}) يثبت أنه برنامج تنفيذي لنظام Windows (PE MZ).`,
      source: 'Magic Bytes Inspector',
      severity: 'CRITICAL',
      verified: true,
      category: 'TOOL_RESULT',
    });
    threatTypes.add('Malware Delivery');
  } else if (magic.mime === 'application/pdf' && extension && extension !== 'pdf') {
    extensionMismatch = true;
    indicators.push({
      name: 'اختلاف التوقيع الثنائي عن امتداد الملف (Extension Mismatch)',
      evidence: `التوقيع الثنائي يشير إلى ملف PDF بينما الامتداد هو .${extension}`,
      source: 'Magic Bytes Inspector',
      severity: 'MEDIUM',
      verified: true,
      category: 'TOOL_RESULT',
    });
  }

  // Check if file format is supported for deep static inspection
  const isSupportedExt =
    SUPPORTED_TEXT_EXTENSIONS.has(extension) ||
    SUPPORTED_DOC_EXTENSIONS.has(extension) ||
    SUPPORTED_ARCHIVE_EXTENSIONS.has(extension) ||
    SUPPORTED_BINARY_EXTENSIONS.has(extension);

  const isSupportedMime =
    magic.mime !== null &&
    !['application/vnd.rar', 'application/x-7z-compressed', 'application/gzip'].includes(magic.mime);

  if (!isSupportedExt && !isSupportedMime) {
    return {
      isSupported: false,
      unsupportedReason: `نوع الملف (.${extension || 'غير معروف'} / Magic Bytes: ${magic.hexPrefix}) غير مدعوم حالياً في محرك التحليل الساكن المباشر.`,
      fileAnalysis: {
        sha256,
        sha1,
        md5,
        file_size: buffer.length,
        extension: extension || null,
        declared_mime_type: declaredMimeType || null,
        detected_mime_type: detectedMime || 'application/octet-stream',
        magic_bytes_hex: magic.hexPrefix,
        extension_mismatch: extensionMismatch,
        static_analysis: 'UNSUPPORTED',
        antivirus: 'NOT_CONFIGURED',
        sandbox: 'NOT_CONFIGURED',
        archive_entries: [],
        extracted_urls: [],
      },
      indicators: [
        {
          name: 'تنسيق ملف غير مدعوم للفحص الساكن العميق (Unsupported File Format)',
          evidence: `الملف "${cleanName}" (التوقيع الثنائي: ${magic.hexPrefix}) لا يتوفر له محلل ساكن متخصص في البيئة الحالية. وفق المبادئ الأمنية، يُصنّف كـ UNKNOWN وليس SAFE.`,
          source: 'File Static Analyzer',
          severity: 'INFO',
          verified: true,
          category: 'TOOL_RESULT',
        },
      ],
      threatTypes: [],
    };
  }

  // Also handle RAR / 7Z / GZ archives if uploaded without specialized unpacker
  if (['rar', '7z', 'gz', 'tar'].includes(extension) || ['application/vnd.rar', 'application/x-7z-compressed'].includes(magic.mime || '')) {
    return {
      isSupported: false,
      unsupportedReason: `الأرشيف من نوع (.${extension || magic.description}) يتطلب أداة فك ضغط خارجية معزولة غير مفعّلة، لذلك لا يمكن فحص محتوياته الداخلية.`,
      fileAnalysis: {
        sha256,
        sha1,
        md5,
        file_size: buffer.length,
        extension: extension || null,
        declared_mime_type: declaredMimeType || null,
        detected_mime_type: detectedMime || 'application/octet-stream',
        magic_bytes_hex: magic.hexPrefix,
        extension_mismatch: extensionMismatch,
        static_analysis: 'UNSUPPORTED',
        antivirus: 'NOT_CONFIGURED',
        sandbox: 'NOT_CONFIGURED',
        archive_entries: [],
        extracted_urls: [],
      },
      indicators: [
        {
          name: 'تعذر فحص المحتوى الداخلي للأرشيف (Archive Format Requires External Extractor)',
          evidence: `الملف المضغوط "${cleanName}" لا يمكن استخراج قائمة ملفاته الداخلية دون محلل ${extension.toUpperCase()} معزول. النتيجة: UNKNOWN.`,
          source: 'Archive Security Analyzer',
          severity: 'LOW',
          verified: true,
          category: 'TOOL_RESULT',
        },
      ],
      threatTypes: [],
    };
  }

  const textRepresentation = buffer.toString('utf8');
  const archiveEntries: string[] = [];
  const extractedUrls = new Set<string>();

  // --- CASE 1: PDF STATIC ANALYSIS ---
  if (magic.mime === 'application/pdf' || extension === 'pdf') {
    if (/\/JavaScript\b|\/JS\b/i.test(textRepresentation)) {
      indicators.push({
        name: 'كود JavaScript مضمّن داخل ملف PDF (Embedded PDF JavaScript)',
        evidence: 'تم العثور على وسوم /JavaScript أو /JS داخل بنية ملف PDF، وهو أسلوب شائع لاستغلال ثغرات قارئ المستندات أو تنفيذ أوامر خبيثة.',
        source: 'PDF Static Analyzer',
        severity: 'HIGH',
        verified: true,
        category: 'TOOL_RESULT',
      });
      threatTypes.add('Malicious Attachments');
      threatTypes.add('Malware Delivery');
    }

    if (/\/OpenAction\b|\/AA\b/i.test(textRepresentation)) {
      indicators.push({
        name: 'إجراء تشغيل تلقائي عند فتح ملف PDF (PDF OpenAction / Auto-Action)',
        evidence: 'يحتوي ملف PDF على خاصية /OpenAction أو /AA التي تنفذ إجراءً تلقائياً بمجرد فتح المستند.',
        source: 'PDF Static Analyzer',
        severity: 'MEDIUM',
        verified: true,
        category: 'TOOL_RESULT',
      });
    }

    if (/\/Launch\b|\/EmbeddedFiles\b/i.test(textRepresentation)) {
      indicators.push({
        name: 'أمر تشغيل برنامج خارجي أو ملف مضمّن في PDF (/Launch or /EmbeddedFiles)',
        evidence: 'يحتوي ملف PDF على كائنات /Launch أو /EmbeddedFiles القادرة على تشغيل أوامر النظام أو إسقاط ملفات.',
        source: 'PDF Static Analyzer',
        severity: 'CRITICAL',
        verified: true,
        category: 'TOOL_RESULT',
      });
      threatTypes.add('Malware Delivery');
    }

    // Extract /URI (...) links and plain URLs in PDF
    const uriMatches = textRepresentation.match(/\/URI\s*\(([^)]+)\)/gi) || [];
    for (const m of uriMatches) {
      const inner = m.replace(/^\/URI\s*\(/i, '').replace(/\)$/, '').trim();
      if (inner) extractedUrls.add(inner);
    }
    extractUrlsFromText(textRepresentation).forEach((u) => extractedUrls.add(u));

    for (const u of extractedUrls) {
      const urlCheck = analyzeUrlStructure(u);
      if (urlCheck.indicators.length > 0) {
        for (const ind of urlCheck.indicators) {
          indicators.push({
            ...ind,
            name: `[رابط خارجي داخل PDF] ${ind.name}`,
          });
        }
        urlCheck.threatTypes.forEach((t) => threatTypes.add(t));
      } else {
        indicators.push({
          name: 'رابط خارجي تفاعلي داخل ملف PDF (External URI Action in PDF)',
          evidence: `يحتوي ملف PDF على توجيه إلى الرابط الخارجي: ${u}`,
          source: 'PDF Static Analyzer',
          severity: 'LOW',
          verified: true,
          category: 'TOOL_RESULT',
        });
      }
    }
  }

  // --- CASE 2: OFFICE DOCUMENTS & MACRO ANALYSIS (OLE2 or OOXML or raw text representation) ---
  const isOfficeDoc =
    SUPPORTED_DOC_EXTENSIONS.has(extension) && extension !== 'pdf' ||
    magic.mime === 'application/x-ole-storage';

  // Inspect ZIP container (either a .zip archive or OOXML .docx/.xlsx/.pptx or .apk)
  if (magic.mime === 'application/zip') {
    try {
      const zip = new AdmZip(buffer);
      const entries = zip.getEntries();

      let totalUncompressed = 0;
      const MAX_ENTRIES = 500;
      const MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024; // 50 MB limit

      if (entries.length > MAX_ENTRIES) {
        indicators.push({
          name: 'عدد ملفات مفرط داخل الأرشيف (Archive Bomb Protection Triggered)',
          evidence: `يحتوي الأرشيف على ${entries.length} ملف، مما يتجاوز الحد الآمن (${MAX_ENTRIES}).`,
          source: 'Archive Security Analyzer',
          severity: 'HIGH',
          verified: true,
          category: 'TOOL_RESULT',
        });
      }

      for (const entry of entries.slice(0, MAX_ENTRIES)) {
        const entryName = entry.entryName;
        archiveEntries.push(entryName);
        totalUncompressed += entry.header.size;

        // 1. Zip Slip / Path Traversal check
        if (entryName.includes('../') || entryName.includes('..\\') || entryName.startsWith('/')) {
          indicators.push({
            name: 'محاولة اختراق المسار عبر الأرشيف (Zip Slip / Path Traversal Attempt)',
            evidence: `المسار الداخلي "${entryName}" يحتوي على تسلسل انتقال للمجلدات الأبوية (../) لكتابة ملفات خارج مجلد العزل.`,
            source: 'Archive Security Analyzer',
            severity: 'CRITICAL',
            verified: true,
            category: 'TOOL_RESULT',
          });
          threatTypes.add('Malware Delivery');
        }

        // 2. Compression Ratio / Zip Bomb check
        if (entry.header.compressedSize > 0) {
          const ratio = entry.header.size / entry.header.compressedSize;
          if (ratio > 100 && entry.header.size > 10 * 1024 * 1024) {
            indicators.push({
              name: 'نسبة ضغط غير طبيعية تشير إلى قنبلة أرشيف (Potential Zip Bomb)',
              evidence: `الملف الداخلي "${entryName}" مضغوط بنسبة ${Math.round(ratio)}:1.`,
              source: 'Archive Security Analyzer',
              severity: 'HIGH',
              verified: true,
              category: 'TOOL_RESULT',
            });
          }
        }

        // 3. Check for VBA Macros inside OOXML (vbaProject.bin)
        if (/vbaProject\.bin/i.test(entryName)) {
          indicators.push({
            name: 'وحدات ماكرو برمجية مضمّنة في مستند Office (Embedded VBA Macro Project)',
            evidence: `تم اكتشاف الملف البرمجي "${entryName}" داخل حاوية مستند Office، مما يسمح بتنفيذ تعليمات VBA تلقائياً عند تفعيل المحتوى.`,
            source: 'Office Document Analyzer',
            severity: 'HIGH',
            verified: true,
            category: 'TOOL_RESULT',
          });
          threatTypes.add('Malicious Attachments');
          threatTypes.add('Malware Delivery');
        }

        // 4. Dangerous inner scripts or executables inside ZIP archive
        const innerExt = entryName.split('.').pop()?.toLowerCase() || '';
        if (['ps1', 'bat', 'cmd', 'vbs', 'js', 'jse', 'wsf', 'hta', 'exe', 'dll', 'scr', 'sh', 'py'].includes(innerExt)) {
          indicators.push({
            name: 'ملف تنفيذي أو سكربت مشبوه داخل الأرشيف المضغوط (Executable / Script Inside Archive)',
            evidence: `يحتوي الأرشيف على ملف قابل للتشغيل: "${entryName}" (.${innerExt}). غالباً ما تستخدم المرفقات المضغوطة لتجاوز بوابات البريد.`,
            source: 'Archive Security Analyzer',
            severity: 'HIGH',
            verified: true,
            category: 'TOOL_RESULT',
          });
          threatTypes.add('Malware Delivery');
          threatTypes.add('Malicious Attachments');

          // Safely inspect inner script content in memory without writing to disk
          if (!entry.isDirectory && entry.header.size <= 1024 * 1024 && totalUncompressed <= MAX_UNCOMPRESSED_BYTES) {
            const innerContent = entry.getData().toString('utf8');
            const scriptIndicators = scanScriptOrBinaryText(innerContent, `داخل الأرشيف (${entryName})`);
            indicators.push(...scriptIndicators);
          }
        }
      }
    } catch (err) {
      indicators.push({
        name: 'أرشيف ZIP تالف أو مشفر (Corrupted or Encrypted ZIP Container)',
        evidence: `تعذر قراءة جدول ملفات ZIP بالكامل: ${err instanceof Error ? err.message : 'خطأ غير معروف'}`,
        source: 'Archive Security Analyzer',
        severity: 'MEDIUM',
        verified: true,
        category: 'TOOL_RESULT',
      });
    }
  }

  // Also check raw buffer / OLE2 for Office Macro & DDE signatures
  if (isOfficeDoc || /vbaProject|AutoOpen|Document_Open|Workbook_Open|DDEAUTO/i.test(textRepresentation)) {
    if (/AutoOpen|AutoExec|Document_Open|Workbook_Open/i.test(textRepresentation)) {
      indicators.push({
        name: 'دالة تشغيل ماكرو تلقائي في مستند Office (Auto-Executing VBA Macro)',
        evidence: 'يحتوي المستند على دوال تنفيذ تلقائي (AutoOpen / Document_Open / Workbook_Open) تعمل فور فتح الملف.',
        source: 'Office Document Analyzer',
        severity: 'CRITICAL',
        verified: true,
        category: 'TOOL_RESULT',
      });
      threatTypes.add('Malware Delivery');
      threatTypes.add('Malicious Attachments');
    } else if (/Sub\s+\w+\(\)|Function\s+\w+\(|Attribute\s+VB_Name|vbaProject/i.test(textRepresentation)) {
      indicators.push({
        name: 'وحدات ماكرو VBA مضمّنة في مستند Office (Embedded Office VBA Macros)',
        evidence: 'تم رصد ترويسات وشيفرات Visual Basic for Applications (VBA) داخل المستند.',
        source: 'Office Document Analyzer',
        severity: 'HIGH',
        verified: true,
        category: 'TOOL_RESULT',
      });
      threatTypes.add('Malicious Attachments');
    }

    if (/DDEAUTO|cmd\.exe|powershell\.exe|WScript\.Shell/i.test(textRepresentation)) {
      indicators.push({
        name: 'أوامر تنفيذ نظام أو استغلال DDE داخل المستند (Command Execution / DDE Exploit)',
        evidence: 'يحتوي المستند على استدعاءات لـ WScript.Shell أو PowerShell أو DDEAUTO لتشغيل أوامر على النظام.',
        source: 'Office Document Analyzer',
        severity: 'CRITICAL',
        verified: true,
        category: 'TOOL_RESULT',
      });
      threatTypes.add('Malware Delivery');
    }
  }

  // --- CASE 3: SCRIPTS, EXECUTABLES & STATIC CODE ANALYSIS ---
  const scriptIndicators = scanScriptOrBinaryText(textRepresentation, cleanName);
  indicators.push(...scriptIndicators);
  if (scriptIndicators.some((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH')) {
    threatTypes.add('Malware Delivery');
  }

  // Determine overall static analysis status
  let staticStatus: FileAnalysisResult['static_analysis'] = 'CLEAN';
  if (indicators.some((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH')) {
    staticStatus = 'MALICIOUS';
  } else if (indicators.length > 0) {
    staticStatus = 'SUSPICIOUS';
  }

  return {
    isSupported: true,
    fileAnalysis: {
      sha256,
      sha1,
      md5,
      file_size: buffer.length,
      extension: extension || null,
      declared_mime_type: declaredMimeType || null,
      detected_mime_type: detectedMime || 'application/octet-stream',
      magic_bytes_hex: magic.hexPrefix,
      extension_mismatch: extensionMismatch,
      static_analysis: staticStatus,
      antivirus: 'NOT_CONFIGURED',
      sandbox: 'NOT_CONFIGURED',
      archive_entries: archiveEntries,
      extracted_urls: Array.from(extractedUrls),
    },
    indicators,
    threatTypes: Array.from(threatTypes),
  };
}

/**
 * Helper to scan scripts / binaries for suspicious patterns, obfuscation, persistence, credential theft.
 */
function scanScriptOrBinaryText(content: string, contextLabel: string): TechnicalIndicator[] {
  const found: TechnicalIndicator[] = [];

  if (/Invoke-Expression|\bIEX\b|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|-EncodedCommand|-enc\s+[A-Za-z0-9+/=]{16,}/i.test(content)) {
    found.push({
      name: `أوامر PowerShell لتحميل أو تنفيذ شيفرة عن بُعد (${contextLabel})`,
      evidence: 'تم رصد أنماط PowerShell خطرة (Invoke-Expression / DownloadString / -EncodedCommand) تُستخدم لتنزيل وتشغيل برمجيات خبيثة في الذاكرة.',
      source: 'Static Script & Binary Analyzer',
      severity: 'CRITICAL',
      verified: true,
      category: 'TOOL_RESULT',
    });
  }

  if (/FromBase64String|eval\s*\(\s*atob\s*\(|String\.fromCharCode\s*\([^)]{30,}\)/i.test(content)) {
    found.push({
      name: `تمويه وتشفير الشيفرة البرمجية Obfuscation (${contextLabel})`,
      evidence: 'استخدام فك التشفير الديناميكي (FromBase64String / eval(atob)) لإخفاء الأوامر الحقيقية عن الفحص التقليدي.',
      source: 'Static Script & Binary Analyzer',
      severity: 'HIGH',
      verified: true,
      category: 'TOOL_RESULT',
    });
  }

  if (/CurrentVersion\\Run|schtasks\s+\/create|crontab\s+-|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i.test(content)) {
    found.push({
      name: `مؤشرات استمرارية وبقاء في النظام Persistence (${contextLabel})`,
      evidence: 'محاولة إضافة مهام مجدولة (schtasks/cron) أو تعديل مفاتيح بدء التشغيل في السجل (Registry Run Keys).',
      source: 'Static Script & Binary Analyzer',
      severity: 'CRITICAL',
      verified: true,
      category: 'TOOL_RESULT',
    });
  }

  if (/mimikatz|lsass\.exe|SAM\b.*SYSTEM|Login Data|Cookies\.sqlite|sekurlsa::logonpasswords/i.test(content)) {
    found.push({
      name: `مؤشرات سرقة بيانات الاعتماد Credential Theft (${contextLabel})`,
      evidence: 'تم رصد سلاسل نصية مرتبطة باستخراج كلمات المرور من الذاكرة (lsass/mimikatz) أو قواعد بيانات المتصفح.',
      source: 'Static Script & Binary Analyzer',
      severity: 'CRITICAL',
      verified: true,
      category: 'TOOL_RESULT',
    });
  }

  if (/VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|UPX0|UPX1/i.test(content)) {
    found.push({
      name: `مؤشرات حقن العمليات أو ضغط الملفات التنفيذية Process Injection / Packer (${contextLabel})`,
      evidence: 'تم العثور على دوال حقن الذاكرة (VirtualAllocEx / WriteProcessMemory / CreateRemoteThread) أو ترويسات ضغط UPX.',
      source: 'Static Script & Binary Analyzer',
      severity: 'HIGH',
      verified: true,
      category: 'TOOL_RESULT',
    });
  }

  return found;
}

/**
 * Sections 11, 12, 13, 14, 15, 16: Deterministic Evidence-Based Verdict & Report Synthesizer
 */
export function synthesizeSecurityVerdict(params: {
  sampleType: SampleType;
  sampleName: string;
  indicators: TechnicalIndicator[];
  threatTypes: string[];
  linkStatus?: LinkStatus;
  targetUrl?: string | null;
  finalUrl?: string | null;
  domain?: string | null;
  domainDetails?: DomainAnalysisDetails | null;
  emailAuth?: EmailAuthenticationResult;
  fileAnalysis?: FileAnalysisResult;
  imageAnalysis?: ImageAnalysisDetails | null;
  reputationResults?: ReputationResult[];
  checksPerformed: string[];
  checksNotPerformed: string[];
  limitations: string[];
  isUnsupportedFile?: boolean;
  unsupportedReason?: string;
}): PhishGuardReport {
  const {
    sampleType,
    sampleName,
    indicators,
    threatTypes,
    linkStatus = 'NOT_APPLICABLE',
    targetUrl = null,
    finalUrl = null,
    domain = null,
    domainDetails = null,
    emailAuth,
    fileAnalysis,
    imageAnalysis = null,
    reputationResults = [],
    checksPerformed,
    checksNotPerformed,
    limitations,
    isUnsupportedFile = false,
    unsupportedReason,
  } = params;

  const analysisId = `PG-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const analyzedAt = new Date().toISOString();

  // Rule: If file is unsupported or insufficient evidence when unreachable without static indicators
  let classification: SecurityClassification = 'SAFE';
  let severity: SeverityLevel = 'INFO';
  let confidence = 85;

  const criticalCount = indicators.filter((i) => i.severity === 'CRITICAL').length;
  const highCount = indicators.filter((i) => i.severity === 'HIGH').length;
  const mediumCount = indicators.filter((i) => i.severity === 'MEDIUM').length;
  const lowCount = indicators.filter((i) => i.severity === 'LOW').length;

  const hasMalwareThreat =
    threatTypes.includes('Malware Delivery') ||
    threatTypes.includes('Malicious Attachments') ||
    fileAnalysis?.static_analysis === 'MALICIOUS' ||
    fileAnalysis?.antivirus === 'DETECTED';

  const hasPhishingThreat =
    threatTypes.includes('Phishing') ||
    threatTypes.includes('Brand Impersonation') ||
    threatTypes.includes('Credential Harvesting') ||
    threatTypes.includes('Smishing') ||
    threatTypes.includes('QR Phishing / Quishing') ||
    threatTypes.includes('Business Email Compromise (BEC)') ||
    threatTypes.includes('Fake Payment Requests');

  if (isUnsupportedFile || fileAnalysis?.static_analysis === 'UNSUPPORTED') {
    classification = 'UNKNOWN';
    severity = 'LOW';
    confidence = 40;
  } else if (criticalCount > 0 || highCount >= 2) {
    if (hasMalwareThreat && !hasPhishingThreat) {
      classification = 'MALICIOUS';
    } else if (hasPhishingThreat) {
      classification = 'PHISHING';
    } else {
      classification = hasMalwareThreat ? 'MALICIOUS' : 'PHISHING';
    }
    severity = criticalCount > 0 ? 'CRITICAL' : 'HIGH';
    confidence = Math.min(96, 78 + criticalCount * 8 + highCount * 5);
  } else if (highCount === 1) {
    classification = hasMalwareThreat ? 'MALICIOUS' : hasPhishingThreat ? 'PHISHING' : 'SUSPICIOUS';
    severity = 'HIGH';
    confidence = 82;
  } else if (mediumCount > 0) {
    classification = 'SUSPICIOUS';
    severity = 'MEDIUM';
    confidence = 72;
  } else if (lowCount > 0) {
    classification = 'SUSPICIOUS';
    severity = 'LOW';
    confidence = 65;
  } else if (sampleType === 'URL' && (linkStatus === 'UNREACHABLE' || linkStatus === 'UNKNOWN')) {
    // Section 3 & 4B: Unreachable URL with no static phishing indicators -> UNKNOWN (cannot confirm safety without reaching page)
    classification = 'UNKNOWN';
    severity = 'LOW';
    confidence = 50;
  } else {
    classification = 'SAFE';
    severity = 'INFO';
    confidence = checksNotPerformed.length > 2 ? 75 : 88;
  }

  // Generate tailored, actionable user recommendations based on Section 14
  const recommendations: string[] = [];
  if (classification === 'PHISHING') {
    recommendations.push(
      'لا تدخل اسم المستخدم أو كلمة المرور في هذه الصفحة أو الرسالة مطلقاً.',
      'لا تشارك رمز التحقق المؤقت (OTP) مع أي طرف تحت أي ظرف.',
      'لا تدخل بيانات البطاقة المصرفية أو تحوّل أي مبالغ مالية.',
      'للتحقق من حسابك، افتح المتصفح واكتب عنوان الموقع الرسمي للبنك أو المؤسسة يدوياً.',
      'أبلغ فريق أمن المعلومات أو الجهة المنتحلة عن هذا الرابط/الرسالة.'
    );
  } else if (classification === 'MALICIOUS') {
    recommendations.push(
      'لا تقم بتشغيل هذا الملف أو فتحه أو تمكين وحدات الماكرو (Enable Content).',
      'اعزل العينة فوراً عن بقية ملفات النظام ولا تشاركها عبر البريد العادي.',
      'إذا تم فتح الملف مسبقاً، افصل الجهاز عن الشبكة فوراً وافحصه بأداة Endpoint Detection / Antivirus موثوقة.',
      'غيّر كلمات المرور الحساسة من جهاز آخر نظيف وموثوق.',
      'حافظ على نسخة من العينة كدليل جنائي رقمي إذا كانت خاضعة لسياسة الاستجابة للحوادث في مؤسستك.'
    );
  } else if (classification === 'SUSPICIOUS') {
    recommendations.push(
      'تجنب التفاعل مع المحتوى أو النقر على الروابط المرفقة حتى اكتمال التحقق.',
      'تحقق من هوية المرسل عبر قناة اتصال رسمية ومستقلة (وليس عبر بيانات الاتصال الواردة داخل الرسالة).',
      'لا تقم بتنزيل المرفقات أو إدخال أي بيانات شخصية.'
    );
  } else if (classification === 'UNKNOWN') {
    recommendations.push(
      'لا يمكن تأكيد سلامة هذه العينة أو خطورتها باستخدام الفحوص المتاحة حالياً؛ تعامل معها بحذر.',
      'لا تفترض أن غياب نتائج الكشف يعني أن العينة آمنة.',
      'تجنب تشغيل الملف أو التفاعل مع الرابط حتى يتم فحصه في بيئة عزل متخصصة (Sandbox).'
    );
  } else {
    recommendations.push(
      'لم تظهر مؤشرات خطر ضمن نطاق الفحوص المنفذة، ولكن تذكّر أن التصنيف SAFE لا يعني ضمان الأمان المطلق.',
      'تحقق دائماً من عنوان النطاق في شريط المتصفح قبل إدخال أي بيانات حساسة.'
    );
  }

  // Build Executive Summary & Final Verdict
  let executiveSummary = '';
  let finalVerdict = '';

  if (classification === 'UNKNOWN' && isUnsupportedFile) {
    executiveSummary = `لم يتمكن النظام من فحص نوع الملف "${sampleName}" (${unsupportedReason || 'تنسيق غير مدعوم'}). تطبيقاً لمبادئ التحليل الجنائي، لا يُصنّف الملف غير المفحوص على أنه آمن.`;
    finalVerdict = `UNKNOWN (مستوى الخطورة: ${severity}) — لم يتمكن النظام من فحص نوع الملف؛ لا يمكن تأكيد سلامة هذه العينة أو خطورتها باستخدام الفحوص المتاحة حالياً.`;
  } else if (classification === 'UNKNOWN') {
    executiveSummary = `تعذر الوصول إلى المحتوى الكامل للعينة "${sampleName}" (حالة الرابط: ${linkStatus})، ولا تتوفر أدلة كافية لإصدار حكم قاطع بالأمان أو الخبث.`;
    finalVerdict = `UNKNOWN (مستوى الخطورة: ${severity}) — لا يمكن تأكيد سلامة هذه العينة أو خطورتها باستخدام الفحوص المتاحة حالياً نظراً لعدم اكتمال الوصول.`;
  } else if (classification === 'PHISHING') {
    const topIndicator = indicators[0]?.name || 'مؤشرات تصيد وانتحال هوية';
    executiveSummary = `أظهر التحليل التقني للعينة "${sampleName}" وجود ${indicators.length} مؤشر(ات) قوية على التصيد الاحتيالي والهندسة الاجتماعية، أبرزها: ${topIndicator}.`;
    finalVerdict = `PHISHING (مستوى الخطورة: ${severity} | الثقة: ${confidence}%) — العينة تمثل تهديد تصيد احتيالي بسبب: ${topIndicator}.`;
  } else if (classification === 'MALICIOUS') {
    const topIndicator = indicators[0]?.name || 'مؤشرات برمجية ضارة';
    executiveSummary = `كشف التحليل الساكن للعينة "${sampleName}" عن وجود ${indicators.length} مؤشر(ات) تقنية عالية الخطورة تشير إلى محتوى خبيث، أبرزها: ${topIndicator}.`;
    finalVerdict = `MALICIOUS (مستوى الخطورة: ${severity} | الثقة: ${confidence}%) — العينة تحتوي على مؤشرات برمجية ضارة: ${topIndicator}.`;
  } else if (classification === 'SUSPICIOUS') {
    const topIndicator = indicators[0]?.name || 'سلوكيات غير معتادة';
    executiveSummary = `تم رصد ${indicators.length} مؤشر(ات) مريبة في العينة "${sampleName}" تستدعي الحذر وتجنب التفاعل، أبرزها: ${topIndicator}.`;
    finalVerdict = `SUSPICIOUS (مستوى الخطورة: ${severity} | الثقة: ${confidence}%) — العينة مشبوهة وتستوجب الحذر بسبب: ${topIndicator}.`;
  } else {
    executiveSummary = `اكتمل فحص العينة "${sampleName}" عبر الأدوات المتاحة دون رصد مؤشرات تصيد أو برمجيات خبيثة في البنية أو المحتوى المفحوص.`;
    finalVerdict = `SAFE (مستوى الخطورة: ${severity} | الثقة: ${confidence}%) — لم تظهر مؤشرات خطر مكتشفة في نطاق الفحوص المنفذة.`;
  }

  const report: PhishGuardReport = {
    analysis_id: analysisId,
    analyzed_at: analyzedAt,
    sample_type: sampleType,
    sample_name: sampleName,
    classification,
    severity,
    confidence,
    link_status: linkStatus,
    target_url: targetUrl,
    final_url: finalUrl,
    domain,
    threat_types: threatTypes,
    indicators,
    reputation_results: reputationResults,
    email_authentication: emailAuth || {
      spf: 'NOT_APPLICABLE',
      dkim: 'NOT_APPLICABLE',
      dmarc: 'NOT_APPLICABLE',
    },
    file_analysis: fileAnalysis || {
      sha256: null,
      detected_mime_type: null,
      static_analysis: 'NOT_RUN',
      antivirus: 'NOT_RUN',
      sandbox: 'NOT_RUN',
    },
    domain_details: domainDetails,
    image_analysis: imageAnalysis,
    content_analysis:
      indicators.length > 0
        ? indicators.map((ind) => `• ${ind.name}: ${ind.evidence}`).join('\n')
        : 'لم يتم رصد عناصر خداع بصري أو شيفرات مشبوهة في المحتوى المفحوص.',
    threat_explanation:
      threatTypes.length > 0
        ? `الأنماط الهجومية المرصودة: ${threatTypes.join('، ')}. تستند هذه النتيجة إلى أدلة تقنية تم التحقق منها.`
        : 'لا توجد أنماط تهديد مؤكدة بناءً على الأدلة الحالية.',
    checks_performed: checksPerformed,
    checks_not_performed: checksNotPerformed,
    limitations,
    user_recommendations: recommendations,
    executive_summary: executiveSummary,
    final_verdict: finalVerdict,
  };

  report.markdown_report = generateArabicMarkdownReport(report);
  return report;
}

/**
 * Section 15: Generates the structured 11-section Arabic Markdown Security Report.
 */
export function generateArabicMarkdownReport(r: PhishGuardReport): string {
  const indicatorsText =
    r.indicators.length > 0
      ? r.indicators
          .map(
            (i, idx) =>
              `${idx + 1}. **${i.name}** [الخطورة: ${i.severity} | المصدر: ${i.source} | محقق: ${i.verified ? 'نعم' : 'استدلالي'}]\n   - الدليل: ${i.evidence}`
          )
          .join('\n')
      : '- لا توجد مؤشرات خطر مرصودة.';

  const repText =
    r.reputation_results.length > 0
      ? r.reputation_results
          .map((rep) => `- **${rep.provider}** (${rep.status}): ${rep.verdict} — ${rep.details} [آخر تحديث: ${rep.last_checked}]`)
          .join('\n')
      : '- لم يتم تسجيل نتائج استعلام خارجية.';

  return `# PHISHGUARD SECURITY ANALYSIS REPORT

### 1. الملخص التنفيذي
- **نوع العينة:** ${r.sample_type}
- **التصنيف الأمني:** ${r.classification}
- **مستوى الخطورة:** ${r.severity}
- **درجة الثقة:** ${r.confidence}/100
- **ملخص سبب الحكم:** ${r.executive_summary}

### 2. معلومات العينة
- **معرّف التحليل:** ${r.analysis_id}
- **اسم العينة:** ${r.sample_name}
- **نوعها:** ${r.sample_type}
- **الرابط أو البصمة الرقمية (SHA-256):** ${r.target_url || r.file_analysis.sha256 || 'غير منطبق'}
- **وقت الفحص:** ${r.analyzed_at}
- **حالة الوصول للرابط:** ${r.link_status}
- **الأدوات المستخدمة:** ${r.checks_performed.join('، ') || 'محرك التحليل الأساسي'}

### 3. نتيجة الفحص
- **حالة عمل الرابط:** ${r.link_status}
- **الوجهة النهائية بعد التوجيه:** ${r.final_url || 'غير متاح'}
- **فحص التحليل الساكن للملف:** ${r.file_analysis.static_analysis}
- **مصادقة البريد (SPF / DKIM / DMARC):** SPF=${r.email_authentication.spf}, DKIM=${r.email_authentication.dkim}, DMARC=${r.email_authentication.dmarc}
- **الفحوص المنفذة:** ${r.checks_performed.join('، ')}
- **الفحوص التي لم تُنفذ:** ${r.checks_not_performed.join('، ') || 'لا يوجد'}

### 4. المؤشرات التقنية
${indicatorsText}

### 5. تحليل النطاق والروابط
- **Domain:** ${r.domain || 'غير متاح'}
- **Subdomain:** ${r.domain_details?.subdomain || 'غير متاح'}
- **Punycode / Homoglyph:** ${r.domain_details?.has_homoglyphs ? `نعم (${r.domain_details.homoglyph_details.join('، ') || 'Punycode'})` : 'لا'}
- **Redirects:** ${r.domain_details?.redirect_chain?.join(' -> ') || 'غير متاح'}
- **DNS:** ${r.domain_details?.dns_records?.join(', ') || 'غير متاح'}
- **IP:** ${r.domain_details?.ip_address || 'غير متاح'}
- **TLS/SSL:** ${r.domain_details?.tls_status || 'غير متاح'}
- **Final URL:** ${r.final_url || 'غير متاح'}

### 6. تحليل المحتوى
${r.content_analysis || 'غير متاح'}

### 7. تحليل التهديد
- **أنواع التهديدات المرصودة:** ${r.threat_types.join('، ') || 'لا توجد تهديدات مصنفة'}
- **التفسير التقني:** ${r.threat_explanation || 'غير متاح'}

### 8. مصادر ونتائج الفحص
${repText}

### 9. الفحوص غير المكتملة والقيود
- **الفحوص غير المنفذة:** ${r.checks_not_performed.join('، ') || 'لا يوجد'}
- **القيود:** ${r.limitations.join(' | ') || 'لا توجد قيود إضافية'}

### 10. التوصية الأمنية
${r.user_recommendations.map((rec) => `- ${rec}`).join('\n')}

### 11. الحكم النهائي
${r.final_verdict}
`;
}
