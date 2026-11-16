import { DomainAnalysisDetails, TechnicalIndicator } from '../types/phishguard';

// Known legitimate brands and their canonical domains
export const KNOWN_BRANDS: Record<string, string[]> = {
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

export const URL_SHORTENERS = new Set([
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
export const BRAND_TYPOSQUAT_PATTERNS: Array<{ brand: string; regex: RegExp; canonical: string }> = [
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
export const HOMOGLYPH_CHAR_MAP: Record<string, string> = {
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
 * private RFC1918, CGNAT, link-local, cloud metadata, IPv4-mapped IPv6, and reserved ranges).
 */
export function isPrivateOrReservedHost(host: string): { blocked: boolean; reason?: string } {
  const cleanHost = host.trim().toLowerCase().replace(/^\[|\]$/g, '');

  if (
    !cleanHost ||
    cleanHost === 'localhost' ||
    cleanHost.endsWith('.localhost') ||
    cleanHost.endsWith('.local') ||
    cleanHost.endsWith('.internal') ||
    cleanHost === 'metadata.google.internal' ||
    cleanHost === 'metadata'
  ) {
    return { blocked: true, reason: `محجوب أمنياً (SSRF Guard): النطاق المحلي أو الداخلي غير مسموح (${cleanHost})` };
  }

  // IPv6 loopback / unspecified / link-local / unique-local / IPv4-mapped IPv6
  if (
    cleanHost === '::1' ||
    cleanHost === '::' ||
    cleanHost === '0:0:0:0:0:0:0:1' ||
    cleanHost === '0:0:0:0:0:0:0:0' ||
    cleanHost.startsWith('fe80:') ||
    cleanHost.startsWith('fc00:') ||
    cleanHost.startsWith('fd00:')
  ) {
    return { blocked: true, reason: `محجوب أمنياً (SSRF Guard): عنوان IPv6 داخلي أو استرجاعي (${cleanHost})` };
  }

  // Check IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (cleanHost.startsWith('::ffff:')) {
    const mappedPart = cleanHost.slice('::ffff:'.length);
    if (mappedPart.includes('.')) {
      return isPrivateOrReservedHost(mappedPart);
    }
    return { blocked: true, reason: `محجوب أمنياً (SSRF Guard): عنوان IPv4-Mapped IPv6 غير مسموح (${cleanHost})` };
  }

  // Block integer/hex/octal single-label numeric hosts (e.g., 2130706433 or 0x7f000001)
  if (/^(0x[0-9a-f]+|\d+)$/i.test(cleanHost)) {
    return { blocked: true, reason: `محجوب أمنياً (SSRF Guard): تمثيل عنوان IP رقمي غير قياسي (${cleanHost})` };
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
    if (a === 100 && b >= 64 && b <= 127) {
      return { blocked: true, reason: 'محجوب أمنياً (SSRF Guard): نطاق Carrier-Grade NAT داخلي (100.64.0.0/10)' };
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
 * Stage A: Pure structural and lexical URL & Domain Intelligence analyzer.
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
      evidence: `الرابط يوجه مباشرة إلى العنوان الرقمي ${hostname} دون نطاق مسجل، وهو سلوك شائع في خوادم التصيد المؤقتة والبرمجيات الخبيثة.`,
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

  // 8. Suspicious keywords in domain or path
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

  // 10. Suspicious High-Risk TLD heuristic
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
