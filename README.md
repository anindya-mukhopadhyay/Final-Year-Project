# AnswerChain-Python

AnswerChain is a distributed academic evaluation and credential integrity platform with tamper-evident blockchain verification.

---

## Architecture Overview

AnswerChain organizes academic operations into a 3-node distributed blockchain network paired with an institutional application server and public verification interfaces:

- **Node 1 (Port 5001)**: University Node — handles answer script registration and teacher assignment.
- **Node 2 (Port 5002)**: Teacher Node — handles examination evaluations and marks submission.
- **Node 3 (Port 5003)**: Authority Node — certifies academic results and registers finalized marksheets.
- **Application Server (Port 8000)**: Institutional portal, Role-Based Access Control (RBAC), and public verification endpoints.

---

## Phase 7A — Public Marksheet Upload Authenticity Checker

Phase 7A introduces a frictionless, public-facing document verification portal where external stakeholders (students, employers, verifiers) can upload an official marksheet PDF to verify its authenticity without needing credentials, a marksheet ID, or blockchain knowledge.

### Verification Flow

```
Public PDF Upload
       ↓
Server-Side Authoritative SHA-256 Calculation
       ↓
Query Distributed Blockchain Ledger (MARKSHEET_REGISTERED records)
       ↓
Compare Uploaded Byte Hash with On-Chain `marksheet_pdf_hash`
       ↓
┌─────────────────────────────────┴─────────────────────────────────┐
│ MATCH                                                             │ MISMATCH
▼                                                                   ▼
VERIFIED                                              TAMPERED_OR_UNKNOWN
(Full credential details & matching proofs)           (Upload hash displayed; document altered or unregistered)
```

1. **Public user uploads PDF**: The document is uploaded via the `/verify/upload` interface or `POST /api/public/verify-upload`.
2. **Server calculates SHA-256**: The server reads the uploaded bytes directly in memory and computes the authoritative cryptographic SHA-256 hash. Client-provided filenames, parameters, or hashes are never trusted.
3. **Server queries registered records**: The server searches the distributed blockchain ledger for `MARKSHEET_REGISTERED` transactions across all validated blocks.
4. **Authoritative Hash Comparison**: The server compares the uploaded document's SHA-256 hash against the `marksheet_pdf_hash` recorded on-chain.
5. **Matching hash = VERIFIED**: If a matching transaction is found, the system confirms the referenced examination result is `FINALIZED` and returns HTTP 200 with the certified student and examination details.
6. **No matching hash = TAMPERED_OR_UNKNOWN**: If no matching hash exists on the distributed ledger, the system returns HTTP 404 with status `TAMPERED_OR_UNKNOWN`.

### Integrity Semantics

> "A matching SHA-256 means the uploaded PDF bytes exactly match the document whose hash was registered in AnswerChain."

> "A mismatch means the uploaded PDF does not match the registered document or is not registered."

*Security Note*: AnswerChain provides mathematical proof that a submitted digital document matches the exact cryptographic hash certified by institutional authority on the distributed ledger. It does not claim to make physical documents impossible to forge, 100% fraud-proof, absolutely immutable against all external vectors, or automatically legally binding in all jurisdictions without applicable administrative approval.

---

## API Endpoints

### Public Endpoints (No Authentication Required)

| Endpoint | Method | Content-Type | Description |
|---|---|---|---|
| `/api/public/verify-upload` | `POST` | `multipart/form-data` | Authoritatively verify an uploaded marksheet PDF against blockchain records |
| `/api/verify/<marksheet_id>` | `GET` | `application/json` | Verify credential by Marksheet ID |
| `/api/qr/<marksheet_id>` | `GET` | `image/png` | Retrieve verification QR code image pointing to `/verify/<marksheet_id>` |

### Verification Upload Specifications

- **Endpoint**: `POST /api/public/verify-upload`
- **Field**: `file` (multipart form-data)
- **Allowed Extension**: `.pdf`
- **MIME Type**: `application/pdf` (or `application/octet-stream` with PDF header)
- **Header Magic Bytes**: File must begin with `%PDF-`
- **Maximum File Size**: 10 MB (10,485,760 bytes)
- **Temporary Handling**: Files are processed safely in-memory or memory buffers. Uploaded files are never permanently saved to disk and never overwrite official marksheets or ledger data.

#### Success Response (`HTTP 200`)
```json
{
  "verified": true,
  "status": "VERIFIED",
  "message": "Marksheet is authentic and matches the registered AnswerChain document.",
  "marksheet_id": "MARKSHEET-461E92F6E79C",
  "student_name": "Sourav Ganguly",
  "university": "TINT",
  "exam_name": "Distributed Systems & Advanced Consensus",
  "final_marks": 88.0,
  "max_marks": 100.0,
  "percentage": 88.0,
  "result_id": "RESULT-4CB8FC677E91",
  "evaluation_id": "EVAL-B3FAD3010D08",
  "pdf_hash": "22e250a8b1d821eb97892d1d83a3fc952ab13b0f3527e22210e3a115112e675c",
  "block_index": 15,
  "transaction_id": "2caab44e692fbc077d281d0739407262304e3d89b0145a044378453322fc750f",
  "result_status": "FINALIZED"
}
```

#### Unmatched / Tampered Response (`HTTP 404`)
```json
{
  "verified": false,
  "status": "TAMPERED_OR_UNKNOWN",
  "message": "The uploaded PDF does not match any registered AnswerChain marksheet.",
  "uploaded_pdf_hash": "9cf93c9e20ab3d2417eeebf318dde35d4f546a9b14d1c5c8e2cf7992a660f8ed"
}
```

---

## Frontend Public Interfaces

- **PDF Upload Verification**: `http://localhost:8000/verify/upload`
- **Marksheet ID Verification**: `http://localhost:8000/verify/index.html` (or `http://localhost:8000/verify/<marksheet_id>`)

Both interfaces provide seamless tab navigation between PDF upload verification and Marksheet ID search, copyable SHA-256 hashes, accessible progress states (`IDLE`, `FILE_SELECTED`, `VERIFYING`, `VERIFIED`, `TAMPERED_OR_UNKNOWN`, `ERROR`), and clear typographic hierarchy.

---

## Automated Testing

Run the comprehensive test suites:

```bash
# Phase 7 Comprehensive Institutional RBAC & Workflow Tests
venv/bin/python3 tests/test_phase7.py

# Phase 7A Public Marksheet Upload Authenticity Checker Tests
venv/bin/python3 tests/test_phase7a.py
```
