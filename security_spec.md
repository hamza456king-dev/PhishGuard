# PhishGuard Firestore Security Specification (`security_spec.md`)

## 1. Data Invariants
1. **Default Deny**: All unmatched paths are strictly denied (`allow read, write: if false;`).
2. **Verified Identity**: All writes require `request.auth != null` and `request.auth.token.email_verified == true`.
3. **PII Isolation**: User email and privacy preferences are stored in `/users/{userId}/private/{docId}` and are strictly readable/writable only by `request.auth.uid == userId` (or verified admin).
4. **Privilege Escalation Prevention**: Users creating `/users/{userId}` can only set `role == 'analyst'` unless they are the bootstrapped verified admin (`hamza.456.king@gmail.com`) or exist in `/admins/{uid}`.
5. **Ownership & Relational Integrity**: Every `ScanRecord` in `/scans/{scanId}` and `AuditLog` in `/audit_logs/{logId}` must have `ownerId == request.auth.uid` and require `exists(/databases/$(database)/documents/users/$(request.auth.uid))` on creation.
6. **Query Enforcement**: `allow list` on `/scans` and `/audit_logs` strictly enforces `resource.data.ownerId == request.auth.uid` (no blanket reads, no `get()` inside `list`).
7. **Temporal Integrity**: `createdAt` must equal `request.time` on create and remain immutable on update; `updatedAt` must equal `request.time`.

## 2. The "Dirty Dozen" Payloads
1. **Shadow Field Injection**: Creating `/scans/scan_1` with an extra undeclared field `{"isVerified": true}` -> Rejected by `hasOnly()`.
2. **Unverified Email Spoofing**: Writing with `email == "hamza.456.king@gmail.com"` but `email_verified == false` -> Rejected by `isVerifiedUser()`.
3. **Self-Assigned Admin Role**: Creating `/users/u1` with `role: "admin"` by non-admin user -> Rejected.
4. **PII Blanket Read**: Authenticated user `u2` reading `/users/u1/private/settings` -> Rejected (`request.auth.uid == userId`).
5. **Cross-Tenant Scan Scraping**: Listing `/scans` without filtering `ownerId == request.auth.uid` -> Rejected by `resource.data.ownerId == request.auth.uid`.
6. **ID Poisoning**: Creating `/scans/invalid$id!@#` or 1.5KB ID -> Rejected by `isValidId()`.
7. **Value Poisoning on Update**: Updating `/scans/scan_1` with `confidence: 999` or string instead of number -> Rejected by `isValidScanRecord(incoming())`.
8. **Immutable Field Mutation**: Updating `ownerId` or `createdAt` on `/scans/scan_1` -> Rejected by immutability gates.
9. **Spoofed Timestamp**: Sending past or future `createdAt` instead of `request.time` -> Rejected by `incoming().createdAt == request.time`.
10. **Orphaned Scan Creation**: Creating `/scans/scan_1` when `/users/$(request.auth.uid)` does not exist -> Rejected by `exists()`.
11. **Audit Log Tampering**: Attempting to `update` or `delete` `/audit_logs/log_1` -> Rejected (`allow update, delete: if false;`).
12. **Oversized String DoS**: Sending a 200KB string in `executive_summary` -> Rejected by `.size() <= 4000`.
