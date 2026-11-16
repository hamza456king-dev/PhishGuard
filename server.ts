import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { MANDATORY_ACCEPTANCE_TESTS } from './src/engine/acceptanceCases';
import { analyzeUrlStructure, synthesizeSecurityVerdict } from './src/engine/analyzers';
import {
  AnalysisRequestInput,
  MultiInputCaseRequest,
  executeFullSecurityAnalysis,
  executeMultiInputCaseAnalysis,
  generateInitialBaselineReports,
} from './src/server/orchestrator';
import { inspectTlsCertificate, resolveAndValidateDns } from './src/server/networkProber';
import { getThreatIntelProvidersStatus, runThreatIntelLookups } from './src/server/threatIntelManager';
import { AnalysisCase, IocLookupResult, PhishGuardReport, TechnicalIndicator } from './src/types/phishguard';

const PORT = 3000;

// Server-side forensic scan store, multi-input cases store & audit log queue
const scanHistoryStore: PhishGuardReport[] = [];
const casesStore: AnalysisCase[] = [];
const auditLogsStore: Array<{
  id: string;
  timestamp: string;
  action: string;
  sample_type: string;
  sample_name: string;
  classification: string;
  severity: string;
}> = [];

// Simple per-IP rate limiter for API protection (Section 8)
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function rateLimiterMiddleware(req: express.Request, res: express.Response, next: express.NextFunction) {
  const clientIp = req.ip || 'local';
  const now = Date.now();
  const windowMs = 60_000;
  const maxRequests = 120;

  const entry = rateLimitMap.get(clientIp);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(clientIp, { count: 1, resetAt: now + windowMs });
    next();
    return;
  }

  entry.count += 1;
  if (entry.count > maxRequests) {
    res.status(429).json({
      error: 'تم تجاوز الحد المسموح من الطلبات في الدقيقة (Rate Limit Exceeded). يرجى المحاولة بعد قليل.',
    });
    return;
  }
  next();
}

async function startServer() {
  const app = express();

  // Security HTTP Headers (Section 8)
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // Allow up to 15MB JSON payload for isolated file/image base64 uploads
  app.use(express.json({ limit: '15mb' }));
  app.use('/api', rateLimiterMiddleware);

  // Initialize deterministic baseline forensic records by executing real analysis engines
  const baseline = await generateInitialBaselineReports();
  scanHistoryStore.push(...baseline);
  for (const r of baseline) {
    auditLogsStore.push({
      id: `AUD-${r.analysis_id}`,
      timestamp: r.analyzed_at,
      action: 'INITIAL_FORENSIC_VERIFICATION',
      sample_type: r.sample_type,
      sample_name: r.sample_name,
      classification: r.classification,
      severity: r.severity,
    });
  }

  // Create initial baseline multi-input case combining related phishing artifacts
  const baselineCaseSamples = baseline.slice(0, 3);
  if (baselineCaseSamples.length > 0) {
    casesStore.push({
      case_id: 'CASE-BASELINE-01',
      created_at: new Date().toISOString(),
      case_name: 'قضية تحقيق متعددة المدخلات: حملة انتحال بريد ومرفق تنفيذي ورابط متجانس',
      overall_classification: 'MALICIOUS',
      overall_severity: 'CRITICAL',
      overall_confidence: 95,
      sample_count: baselineCaseSamples.length,
      samples: baselineCaseSamples,
      executive_summary:
        'تحقيق جنائي مركّب يربط بين بريد إلكتروني منتحل الهوية ومرفق تنفيذي مزدوج الامتداد ورابط Homoglyph خادع، مع الاحتفاظ بنتائج كل عينة بصورة مستقلة.',
      consolidated_summary:
        'تحقيق جنائي مركّب يربط بين بريد إلكتروني منتحل الهوية ومرفق تنفيذي مزدوج الامتداد ورابط Homoglyph خادع، مع الاحتفاظ بنتائج كل عينة بصورة مستقلة.',
      consolidated_recommendations: [
        'عزل البريد الإلكتروني والمرفق التنفيذي فوراً وعدم فتحه.',
        'حظر النطاق المنتحل وعنوان IP المرسل على مستوى بوابة البريد والجدار الناري.',
      ],
    });
  }

  // GET /api/health & system status
  app.get('/api/status', (_req, res) => {
    const providers = getThreatIntelProvidersStatus();
    res.json({
      status: 'OPERATIONAL',
      engineVersion: 'PhishGuard Forensic Core 2.4',
      serverTime: new Date().toISOString(),
      isolatedProberActive: true,
      ssrfProtectionActive: true,
      zipBombGuardActive: true,
      totalScansProcessed: scanHistoryStore.length,
      totalCasesProcessed: casesStore.length,
      providers,
      auditLogs: auditLogsStore.slice(0, 50),
    });
  });

  // GET /api/cases - list all multi-input investigation cases
  app.get('/api/cases', (_req, res) => {
    res.json({ cases: casesStore });
  });

  // POST /api/analyze-case - analyze multiple inputs together under a single investigation case
  app.post('/api/analyze-case', async (req, res) => {
    try {
      const body = req.body as MultiInputCaseRequest;
      if (!body || !Array.isArray(body.inputs) || body.inputs.length === 0) {
        res.status(400).json({ error: 'يرجى إضافة عينة واحدة على الأقل داخل القضية متعددة المدخلات.' });
        return;
      }

      const analysisCase = await executeMultiInputCaseAnalysis(body);
      casesStore.unshift(analysisCase);
      for (const sampleReport of analysisCase.samples) {
        scanHistoryStore.unshift(sampleReport);
      }

      auditLogsStore.unshift({
        id: `AUD-${Date.now().toString(36).toUpperCase()}`,
        timestamp: analysisCase.created_at,
        action: `ANALYZE_MULTI_CASE (${analysisCase.sample_count} samples)`,
        sample_type: 'MULTI_CASE',
        sample_name: analysisCase.case_name,
        classification: analysisCase.overall_classification,
        severity: analysisCase.overall_severity,
      });

      res.json(analysisCase);
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'حدث خطأ أثناء تحليل القضية متعددة المدخلات.',
      });
    }
  });

  // POST /api/ioc-lookup - live Indicator of Compromise (URL, Domain, IP, SHA-256) lookup
  app.post('/api/ioc-lookup', async (req, res) => {
    try {
      const rawQuery = typeof req.body?.query === 'string' ? req.body.query.trim() : '';
      const consentExternal = req.body?.consentExternal !== false;
      if (!rawQuery) {
        res.status(400).json({ error: 'يرجى إدخال مؤشر اختراق صالح (رابط URL، نطاق Domain، عنوان IP، أو بصمة SHA-256).' });
        return;
      }

      const now = new Date().toISOString();
      let indicatorType: IocLookupResult['indicatorType'] = 'DOMAIN';
      if (/^[a-fA-F0-9]{64}$/.test(rawQuery)) {
        indicatorType = 'SHA256';
      } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(rawQuery)) {
        indicatorType = 'IP';
      } else if (/^https?:\/\//i.test(rawQuery)) {
        indicatorType = 'URL';
      }

      const indicators: TechnicalIndicator[] = [];
      let domainForLookup: string | null = null;
      let urlForLookup: string | null = null;
      let ipForLookup: string | null = null;
      let sha256ForLookup: string | null = null;
      let dnsRecords: string[] = [];
      let tlsStatus: string | undefined;

      if (indicatorType === 'SHA256') {
        sha256ForLookup = rawQuery.toLowerCase();
      } else if (indicatorType === 'IP') {
        ipForLookup = rawQuery;
        const struct = analyzeUrlStructure(`http://${rawQuery}`);
        indicators.push(...struct.indicators);
      } else if (indicatorType === 'URL') {
        urlForLookup = rawQuery;
        const struct = analyzeUrlStructure(rawQuery);
        indicators.push(...struct.indicators);
        domainForLookup = struct.details.domain;
        if (domainForLookup) {
          const dnsRes = await resolveAndValidateDns(domainForLookup);
          dnsRecords = dnsRes.records;
          ipForLookup = dnsRes.primaryIp;
          if (rawQuery.toLowerCase().startsWith('https://')) {
            tlsStatus = await inspectTlsCertificate(domainForLookup);
          }
        }
      } else {
        const cleanDom = rawQuery.toLowerCase().replace(/^www\./, '');
        domainForLookup = cleanDom;
        const struct = analyzeUrlStructure(`https://${cleanDom}`);
        indicators.push(...struct.indicators);
        const dnsRes = await resolveAndValidateDns(cleanDom);
        dnsRecords = dnsRes.records;
        ipForLookup = dnsRes.primaryIp;
        tlsStatus = await inspectTlsCertificate(cleanDom);
      }

      const intel = await runThreatIntelLookups({
        domain: domainForLookup,
        url: urlForLookup,
        sha256: sha256ForLookup,
        ipAddress: ipForLookup,
        consentExternal,
      });

      const qLower = rawQuery.toLowerCase();
      const matchedHistory = scanHistoryStore
        .filter((s) => {
          return (
            (s.domain && s.domain.toLowerCase().includes(qLower)) ||
            (s.target_url && s.target_url.toLowerCase().includes(qLower)) ||
            (s.file_analysis.sha256 && s.file_analysis.sha256.toLowerCase() === qLower) ||
            s.sample_name.toLowerCase().includes(qLower)
          );
        })
        .map((s) => ({
          analysis_id: s.analysis_id,
          analyzed_at: s.analyzed_at,
          sample_type: s.sample_type,
          sample_name: s.sample_name,
          classification: s.classification,
          severity: s.severity,
        }));

      for (const m of matchedHistory) {
        if (m.classification === 'MALICIOUS' || m.classification === 'PHISHING') {
          indicators.push({
            name: `تطابق في السجل الجنائي المحلي (${m.classification})`,
            evidence: `ظهر هذا المؤشر سابقاً في التحليل رقم ${m.analysis_id} (${m.sample_name}) بتصنيف ${m.classification}.`,
            source: 'Local Forensic History Store',
            severity: m.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
            verified: true,
            category: 'TOOL_RESULT',
          });
        }
      }

      const risk = synthesizeSecurityVerdict({
        sampleType: 'URL',
        sampleName: rawQuery,
        indicators,
        threatTypes: [],
        checksPerformed: intel.checksPerformed,
        checksNotPerformed: intel.checksNotPerformed,
        limitations: [],
      });

      const result: IocLookupResult = {
        query: rawQuery,
        indicatorType,
        queriedAt: now,
        classification: risk.classification,
        severity: risk.severity,
        confidence: risk.confidence,
        summaryAr:
          indicators.length > 0
            ? `تم رصد ${indicators.length} مؤشر تقني مرتبط بالمؤشر (${rawQuery}). التصنيف المقدر: ${risk.classification}.`
            : matchedHistory.length > 0
            ? `تم العثور على ${matchedHistory.length} سجل سابق في قاعدة البيانات المحلية للمؤشر (${rawQuery}).`
            : dnsRecords.length > 0
            ? `النطاق (${rawQuery}) نشط ويحتوي على سجلات DNS (${dnsRecords.join(', ')}) دون مؤشرات تصيد بنيوية مباشرة.`
            : `لا توجد مؤشرات تهديد مؤكدة للمؤشر (${rawQuery}) ضمن المصادر المتاحة حالياً (غياب النتيجة لا يعني الأمان المطلق).`,
        structuralIndicators: indicators,
        reputationResults: intel.results,
        dnsRecords: dnsRecords.length > 0 ? dnsRecords : undefined,
        ipAddress: ipForLookup,
        tlsStatus,
        matchedHistory,
      };

      auditLogsStore.unshift({
        id: `AUD-${Date.now().toString(36).toUpperCase()}`,
        timestamp: now,
        action: `IOC_LOOKUP_${indicatorType}`,
        sample_type: 'URL',
        sample_name: rawQuery,
        classification: result.classification,
        severity: result.severity,
      });

      res.json(result);
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'تعذر إتمام استعلام مؤشر الاختراق IOC.',
      });
    }
  });

  // GET /api/scans - list all stored scans + real aggregated metrics
  app.get('/api/scans', (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';
    const classification = typeof req.query.classification === 'string' ? req.query.classification : 'ALL';
    const severity = typeof req.query.severity === 'string' ? req.query.severity : 'ALL';
    const sampleType = typeof req.query.sampleType === 'string' ? req.query.sampleType : 'ALL';

    const filtered = scanHistoryStore.filter((item) => {
      if (classification !== 'ALL' && item.classification !== classification) return false;
      if (severity !== 'ALL' && item.severity !== severity) return false;
      if (sampleType !== 'ALL' && item.sample_type !== sampleType) return false;
      if (q) {
        const hay = [
          item.analysis_id,
          item.sample_name,
          item.domain || '',
          item.target_url || '',
          item.file_analysis.sha256 || '',
          item.executive_summary,
        ]
          .join(' ')
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    // Compute real telemetry metrics from actual stored reports
    const stats = {
      total: scanHistoryStore.length,
      safe: scanHistoryStore.filter((s) => s.classification === 'SAFE').length,
      suspicious: scanHistoryStore.filter((s) => s.classification === 'SUSPICIOUS').length,
      phishing: scanHistoryStore.filter((s) => s.classification === 'PHISHING').length,
      malicious: scanHistoryStore.filter((s) => s.classification === 'MALICIOUS').length,
      unknown: scanHistoryStore.filter((s) => s.classification === 'UNKNOWN').length,
      critical: scanHistoryStore.filter((s) => s.severity === 'CRITICAL').length,
      byType: {
        URL: scanHistoryStore.filter((s) => s.sample_type === 'URL').length,
        MESSAGE: scanHistoryStore.filter((s) => s.sample_type === 'MESSAGE').length,
        EMAIL: scanHistoryStore.filter((s) => s.sample_type === 'EMAIL').length,
        FILE: scanHistoryStore.filter((s) => s.sample_type === 'FILE').length,
        IMAGE: scanHistoryStore.filter((s) => s.sample_type === 'IMAGE').length,
      },
    };

    res.json({
      stats,
      scans: filtered,
    });
  });

  // POST /api/analyze - run full security analysis on any sample type
  app.post('/api/analyze', async (req, res) => {
    try {
      const body = req.body as AnalysisRequestInput;
      if (!body || !body.sampleType) {
        res.status(400).json({ error: 'يرجى تحديد نوع العينة (sampleType) والمدخلات المطلوبة للفحص.' });
        return;
      }

      const report = await executeFullSecurityAnalysis(body);
      scanHistoryStore.unshift(report);

      auditLogsStore.unshift({
        id: `AUD-${Date.now().toString(36).toUpperCase()}`,
        timestamp: report.analyzed_at,
        action: `ANALYZE_${report.sample_type}`,
        sample_type: report.sample_type,
        sample_name: report.sample_name,
        classification: report.classification,
        severity: report.severity,
      });

      res.json(report);
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'حدث خطأ أثناء تنفيذ التحليل الأمني.',
      });
    }
  });

  // DELETE /api/scans/:id - delete a scan report
  app.delete('/api/scans/:id', (req, res) => {
    const { id } = req.params;
    const idx = scanHistoryStore.findIndex((s) => s.analysis_id === id);
    if (idx !== -1) {
      const removed = scanHistoryStore.splice(idx, 1)[0];
      auditLogsStore.unshift({
        id: `AUD-${Date.now().toString(36).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        action: 'DELETE_REPORT',
        sample_type: removed.sample_type,
        sample_name: removed.sample_name,
        classification: removed.classification,
        severity: removed.severity,
      });
    }
    res.json({ deleted: true, id });
  });

  // GET /api/tests - list the 13 mandatory acceptance tests
  app.get('/api/tests', (_req, res) => {
    res.json({ tests: MANDATORY_ACCEPTANCE_TESTS });
  });

  // POST /api/tests/run-all - execute all 13 mandatory acceptance tests against the live engine
  app.post('/api/tests/run-all', async (_req, res) => {
    try {
      const results = [];
      for (const tc of MANDATORY_ACCEPTANCE_TESTS) {
        const report = await executeFullSecurityAnalysis({
          sampleType: tc.sampleType,
          sampleName: tc.titleAr,
          ...tc.payload,
          consentExternal: false,
          useGeminiEnrichment: false,
        });

        const classificationMatch = tc.expectedClassification.includes(report.classification);
        const linkStatusMatch =
          !tc.expectedLinkStatus || tc.expectedLinkStatus.includes(report.link_status);

        results.push({
          testCase: tc,
          report,
          passed: classificationMatch && linkStatusMatch,
        });
      }

      res.json({
        total: results.length,
        passedCount: results.filter((r) => r.passed).length,
        results,
      });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'فشل تشغيل اختبارات القبول.',
      });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PhishGuard Security Engine listening on http://localhost:${PORT}`);
  });
}

startServer();
