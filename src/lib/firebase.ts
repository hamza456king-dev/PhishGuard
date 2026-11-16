import { initializeApp } from 'firebase/app';
import {
  GoogleAuthProvider,
  User,
  getAuth,
  onAuthStateChanged,
  signInWithPopup,
  signOut,
} from 'firebase/auth';
import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocFromServer,
  getFirestore,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  where,
} from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';
import { PhishGuardReport } from '../types/phishguard';

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

// Validate connection to Firestore on boot per firebase-integration-rpc
async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
testConnection();

export async function signInWithGoogle(): Promise<User> {
  const provider = new GoogleAuthProvider();
  const cred = await signInWithPopup(auth, provider);
  await ensureUserProfileAndSettings(cred.user);
  return cred.user;
}

export async function signOutUser(): Promise<void> {
  await signOut(auth);
}

/**
 * Ensures the authenticated user's public profile (/users/{uid}) and isolated private settings
 * (/users/{uid}/private/settings) exist and strictly match firestore.rules schema.
 */
export async function ensureUserProfileAndSettings(user: User): Promise<void> {
  if (!user.emailVerified) return;

  const userPath = `users/${user.uid}`;
  const userRef = doc(db, 'users', user.uid);

  try {
    const existingSnap = await getDoc(userRef);
    if (!existingSnap.exists()) {
      const isAdminEmail = user.email === 'hamza.456.king@gmail.com';
      await setDoc(userRef, {
        uid: user.uid,
        displayName: (user.displayName || user.email?.split('@')[0] || 'Analyst').slice(0, 100),
        role: isAdminEmail ? 'admin' : 'analyst',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, userPath);
  }

  const privatePath = `users/${user.uid}/private/settings`;
  const privateRef = doc(db, 'users', user.uid, 'private', 'settings');
  try {
    const privSnap = await getDoc(privateRef);
    if (!privSnap.exists()) {
      await setDoc(privateRef, {
        uid: user.uid,
        email: (user.email || 'analyst@example.com').slice(0, 254),
        consentExternalScans: false,
        retentionDays: 90,
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, privatePath);
  }
}

/**
 * Persists a PhishGuardReport to Firestore (/scans/{analysis_id}) and logs an AuditLog (/audit_logs/{logId})
 * when the user is signed in with a verified email.
 */
export async function saveScanReportToFirestore(report: PhishGuardReport): Promise<void> {
  const user = auth.currentUser;
  if (!user || !user.emailVerified) return;

  await ensureUserProfileAndSettings(user);

  const safeId = report.analysis_id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 128) || `PG_${Date.now()}`;
  const scanPath = `scans/${safeId}`;
  const scanRef = doc(db, 'scans', safeId);

  const payloadStr = JSON.stringify(report).slice(0, 95000);

  try {
    await setDoc(scanRef, {
      analysis_id: safeId,
      ownerId: user.uid,
      analyzed_at: report.analyzed_at.slice(0, 64),
      sample_type: report.sample_type,
      sample_name: (report.sample_name || 'Sample').slice(0, 500),
      classification: report.classification,
      severity: report.severity,
      confidence: Math.max(0, Math.min(100, Math.round(report.confidence))),
      link_status: report.link_status,
      domain: (report.domain || '').slice(0, 255),
      sha256: (report.file_analysis?.sha256 || '').slice(0, 128),
      executive_summary: (report.executive_summary || '').slice(0, 4000),
      final_verdict: (report.final_verdict || '').slice(0, 2000),
      report_payload: payloadStr,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, scanPath);
  }

  const logId = `LOG_${safeId}`.slice(0, 128);
  const logPath = `audit_logs/${logId}`;
  try {
    await setDoc(doc(db, 'audit_logs', logId), {
      id: logId,
      ownerId: user.uid,
      action: `SCAN_${report.sample_type}`,
      sample_type: report.sample_type,
      classification: report.classification,
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, logPath);
  }
}

export async function deleteScanReportFromFirestore(analysisId: string): Promise<void> {
  const user = auth.currentUser;
  if (!user || !user.emailVerified) return;

  const safeId = analysisId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 128);
  const scanPath = `scans/${safeId}`;
  try {
    await deleteDoc(doc(db, 'scans', safeId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, scanPath);
  }
}

export function subscribeUserScans(
  userId: string,
  onUpdate: (reports: PhishGuardReport[]) => void
): () => void {
  const q = query(collection(db, 'scans'), where('ownerId', '==', userId));
  return onSnapshot(
    q,
    (snapshot) => {
      const list: PhishGuardReport[] = [];
      snapshot.forEach((docSnap) => {
        const data = docSnap.data();
        if (data.report_payload) {
          try {
            list.push(JSON.parse(data.report_payload) as PhishGuardReport);
          } catch {
            // Ignore malformed JSON
          }
        }
      });
      list.sort((a, b) => b.analyzed_at.localeCompare(a.analyzed_at));
      onUpdate(list);
    },
    (error) => {
      handleFirestoreError(error, OperationType.LIST, 'scans');
    }
  );
}

export { onAuthStateChanged };
export type { User };
