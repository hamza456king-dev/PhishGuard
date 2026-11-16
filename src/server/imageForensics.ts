import jsQR from 'jsqr';
import { PNG } from 'pngjs';
import { ImageAnalysisDetails, TechnicalIndicator } from '../types/phishguard';
import { analyzeMessageContent, analyzeUrlStructure, detectMagicBytesMime, extractUrlsFromText } from '../engine/analyzers';
import { analyzeImageWithGeminiVision } from './geminiEngine';

export interface ServerImageAnalysisOutput {
  imageDetails: ImageAnalysisDetails;
  indicators: TechnicalIndicator[];
  threatTypes: string[];
  extractedUrl: string | null;
  domain: string | null;
  checksPerformed: string[];
  checksNotPerformed: string[];
}

/**
 * Decodes QR code from a PNG buffer on the server using pngjs + jsQR.
 */
export function decodeQrFromPngBuffer(buffer: Buffer): { payload: string | null; dimensions: string | null } {
  try {
    const png = PNG.sync.read(buffer);
    const code = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
    return {
      payload: code ? code.data : null,
      dimensions: `${png.width}x${png.height} px`,
    };
  } catch {
    return { payload: null, dimensions: null };
  }
}

/**
 * Inspects basic JPEG EXIF / PNG tEXt chunks safely from buffer.
 */
export function extractImageMetadataSummary(buffer: Buffer, mimeType: string | null): string {
  const asciiSlice = buffer.subarray(0, Math.min(buffer.length, 4096)).toString('latin1');
  const notes: string[] = [];

  if (mimeType === 'image/jpeg' && asciiSlice.includes('Exif')) {
    notes.push('تحتوي الصورة على ترويسة بيانات وصفية EXIF.');
  }
  if (/Photoshop|GIMP|Canva|Figma/i.test(asciiSlice)) {
    const editor = asciiSlice.match(/Photoshop|GIMP|Canva|Figma/i)?.[0];
    notes.push(`تم رصد أثر برنامج تحرير صور في البيانات الوصفية (${editor}).`);
  }

  return notes.length > 0 ? notes.join(' ') : 'لا توجد علامات تلاعب أو برامج تحرير صريحة في ترويسة الملف.';
}

/**
 * Section 8: Complete Server-Side Image Security Analyzer (QR Decoder + OCR + Visual Brand + URL Pipeline)
 */
export async function analyzeImageSampleServer(params: {
  fileName: string;
  buffer?: Buffer;
  clientQrDecoded?: string | null;
  simulatedDescription?: string | null;
}): Promise<ServerImageAnalysisOutput> {
  const { fileName, buffer, clientQrDecoded, simulatedDescription } = params;
  const indicators: TechnicalIndicator[] = [];
  const threatTypes = new Set<string>();
  const checksPerformed: string[] = [];
  const checksNotPerformed: string[] = ['تحليل إخفاء البيانات داخل البكسلات (Steganography Binary Bit-Plane Analysis)'];

  let qrPayload: string | null = clientQrDecoded || null;
  let dimensions: string | null = null;
  let exifSummary = 'غير متاح';
  let ocrText: string | null = simulatedDescription || null;
  let visualBrand: string | null = null;

  if (buffer && buffer.length > 0) {
    const magic = detectMagicBytesMime(buffer);
    checksPerformed.push('Magic Bytes Image Header Verification');
    exifSummary = extractImageMetadataSummary(buffer, magic.mime);
    checksPerformed.push('Image Metadata & Header Inspection');

    if (magic.mime === 'image/png' && !qrPayload) {
      const pngQr = decodeQrFromPngBuffer(buffer);
      if (pngQr.payload) qrPayload = pngQr.payload;
      if (pngQr.dimensions) dimensions = pngQr.dimensions;
      checksPerformed.push('Server-Side PNG QR Decoder (jsQR)');
    }

    // Call Gemini Vision for OCR and Visual Deception analysis if configured
    if (magic.mime && magic.mime.startsWith('image/')) {
      const visionRes = await analyzeImageWithGeminiVision(buffer, magic.mime);
      if (visionRes.executed) {
        checksPerformed.push('Gemini Vision OCR & Visual Brand Analysis');
        if (visionRes.ocrText) ocrText = visionRes.ocrText;
        if (visionRes.detectedBrand) visualBrand = visionRes.detectedBrand;
        if (visionRes.qrOrUrlInImage && !qrPayload) {
          qrPayload = visionRes.qrOrUrlInImage;
        }
        if (visionRes.visualDeceptionNote) {
          indicators.push({
            name: 'ملاحظة فحص بصري للذكاء الاصطناعي (AI Visual Inspection Observation)',
            evidence: visionRes.visualDeceptionNote,
            source: 'Gemini Vision Inspector',
            severity: visionRes.isSuspiciousVisual ? 'HIGH' : 'INFO',
            verified: false,
            category: 'AI_OBSERVATION',
          });
        }
      } else {
        checksNotPerformed.push('Gemini Vision OCR (يتطلب مفتاح GEMINI_API_KEY صالح)');
      }
    }
  } else if (clientQrDecoded || simulatedDescription) {
    checksPerformed.push('QR Code Payload & Text Forensics');
  }

  const allExtractedUrls = new Set<string>();
  if (qrPayload && /^https?:\/\//i.test(qrPayload.trim())) {
    allExtractedUrls.add(qrPayload.trim());
  }
  if (ocrText) {
    extractUrlsFromText(ocrText).forEach((u) => allExtractedUrls.add(u));
    // Run message social engineering analysis on OCR text
    const ocrMsgAnalysis = analyzeMessageContent(ocrText);
    for (const ind of ocrMsgAnalysis.indicators) {
      indicators.push({
        ...ind,
        name: `[نص مستخرج من الصورة OCR] ${ind.name}`,
      });
    }
    ocrMsgAnalysis.threatTypes.forEach((t) => threatTypes.add(t));
  }

  let primaryUrl: string | null = null;
  let primaryDomain: string | null = null;

  if (qrPayload) {
    checksPerformed.push('QR Code Decoder');
    if (/^https?:\/\//i.test(qrPayload.trim())) {
      const qrUrlAnalysis = analyzeUrlStructure(qrPayload.trim());
      primaryUrl = qrUrlAnalysis.normalizedUrl || qrPayload.trim();
      primaryDomain = qrUrlAnalysis.details.domain;
      checksPerformed.push('URL Structural Analysis on Decoded QR Link');

      if (qrUrlAnalysis.indicators.length > 0) {
        indicators.push({
          name: 'رمز QR مضمّن يوجه إلى رابط مشبوه أو تصيد (QR Phishing / Quishing)',
          evidence: `يحتوي رمز الاستجابة السريعة (QR Code) على الرابط: ${primaryUrl} الذي يحمل مؤشرات خطر تقنية.`,
          source: 'QR Code Decoder & URL Analyzer',
          severity: 'CRITICAL',
          verified: true,
          category: 'TOOL_RESULT',
        });
        threatTypes.add('QR Phishing / Quishing');
        threatTypes.add('Phishing');

        for (const ind of qrUrlAnalysis.indicators) {
          indicators.push({
            ...ind,
            name: `[الرابط داخل رمز QR] ${ind.name}`,
          });
        }
        qrUrlAnalysis.threatTypes.forEach((t) => threatTypes.add(t));
      } else {
        indicators.push({
          name: 'رمز QR يحتوي على رابط خارجي (Decoded QR URL)',
          evidence: `الرابط المستخرج من رمز QR هو: ${primaryUrl}. ملاحظة: وجود رمز QR وحده لا يعني أن الصورة خبيثة.`,
          source: 'QR Code Decoder',
          severity: 'INFO',
          verified: true,
          category: 'TOOL_RESULT',
        });
      }
    }
  }

  // Also analyze any other URLs extracted via OCR
  for (const u of allExtractedUrls) {
    if (u !== qrPayload?.trim()) {
      const uRes = analyzeUrlStructure(u);
      if (!primaryUrl) {
        primaryUrl = uRes.normalizedUrl || u;
        primaryDomain = uRes.details.domain;
      }
      for (const ind of uRes.indicators) {
        indicators.push({
          ...ind,
          name: `[رابط ظاهر في الصورة] ${ind.name}`,
        });
      }
      uRes.threatTypes.forEach((t) => threatTypes.add(t));
    }
  }

  return {
    imageDetails: {
      ocr_text: ocrText,
      qr_decoded_payload: qrPayload,
      extracted_urls: Array.from(allExtractedUrls),
      visual_brand_detected: visualBrand,
      exif_summary: exifSummary,
      dimensions,
      steganography_note:
        'تنبيه منهجي: الفحص المنفذ يغطي تحليل الرؤية الضوئية (OCR) ورموز QR والترويسة الثنائية، ولا يستبعد وجود بيانات مخفية بتقنية Steganography داخل البكسلات دون أداة تحليل جنائي متخصصة.',
    },
    indicators,
    threatTypes: Array.from(threatTypes),
    extractedUrl: primaryUrl,
    domain: primaryDomain,
    checksPerformed,
    checksNotPerformed,
  };
}
