# MOSSIP Engineering Changelog & Audit Trace

This document maps all identified architectural, security, algorithmic, and presentation findings across phases P0–P3 directly to implementation commits and verification artifacts.

---

## Phase P0: Security & Correctness

### [P0-1] Don't Trust Client Landmarks
- **Finding:** Client-sent landmarks were accepted with hard-coded 0.99 confidence and used directly for challenge verification, allowing synthetic landmarks with a still photo to pass. Fabricated landmarks from `estimateFromFramePixels` generated perfect EAR/MAR from any skin blob.
- **Resolution:**
  - Removed fabricated landmark fallback from `ClientLandmarkAnalyzer.java`, returning `NO_FACE_DETECTED` (`Optional.empty()`) when no real face is identified.
  - Implemented pure-Java `ServerFaceDetector.java` performing skin chrominance segmentation in YCbCr space, morphological connected component bounding, and eye/mouth contrast verification.
  - Implemented `LandmarkCrossValidator.java` enforcing bounding box IoU ($\ge 0.20$), pupil-to-pupil distance ratio ($\le 0.35$), and pose yaw delta ($\le 35^\circ$). Mismatches generate `LANDMARK_MISMATCH` audit events and abort verification.
  - Implemented pixel corroboration in `ChallengeVerifier.java` validating eye region luma deltas (blink) and pixel sum-of-absolute-differences motion (turn/nod).
- **Commit:** `feat(security): implement P0 anti-spoofing, audit signing, session auth, and lockout`
- **Tests:** `DefaultLivenessEngineTest`, `LivenessServerWebSocketTest`

### [P0-2] Close the Anti-Adversarial Leak
- **Finding:** Public WebSocket decision payloads broadcasted raw scores and session IDs. Unauthenticated `/api/audit/{sessionId}` leaked attack classification (`PRINT_ATTACK`, `SCREEN_REPLAY`, `VIDEO_INJECTION`) and PAD subscores. `/api/audit` dumped the entire event store to any anonymous caller.
- **Resolution:**
  - Redacted public WebSocket decision payload in `WebSocketHandler.java` to only return high-level decision enum and localized generic user message. Raw scores and session IDs are suppressed unless authenticated in Judge Mode.
  - Protected `/api/audit*`, `/api/policy*`, and `/api/supervisor/override` endpoints behind constant-time Bearer token verification (`LIVENESS_ADMIN_TOKEN`).
  - Added token-gated "Judge Mode" toggle in web UI (`btnJudgeMode`) with full diagnostic telemetry unlocked only when authenticated.
- **Commit:** `feat(security): implement P0 anti-spoofing, audit signing, session auth, and lockout`
- **Tests:** `LivenessServerRestTest#testAuditEndpointsRequireAdminToken`, `LivenessServerWebSocketTest#testAdversarialScoreLeakPrevented`

### [P0-3] AuthN/Z, Workflow Binding, Demo Default
- **Finding:** Clients selected arbitrary workflows via `?workflow=`, allowing selection of weak policies (e.g. `RESIDENT_AUTH` with passive-only). `LIVENESS_DEMO` defaulted to true. Supervisor override was unauthenticated in demo mode. No Origin verification or connection/bandwidth limits existed.
- **Resolution:**
  - Changed `demoMode` default to `false` in `ServerConfig.java`.
  - Added authenticated `POST /api/v1/sessions` endpoint issuing HMAC-SHA256 signed session tokens encoding workflow, client identity, nonce, and expiration.
  - Enforced signed session tokens on WebSocket connection in `WebSocketHandler.java` (with graceful fallback only if `demoMode=true`).
  - Implemented Origin allow-list checks, per-IP connection limits (max 10 concurrent sockets), and per-session byte limits (15 MB).
  - Hardened `/api/supervisor/override` requiring a recent (<5 min), single-use `ACCEPTED` `SUPERVISOR_AUTH` session different from target.
- **Commit:** `feat(security): implement P0 anti-spoofing, audit signing, session auth, and lockout`
- **Tests:** `LivenessServerRestTest#testSessionTokenCreationAndPolicyBinding`, `LivenessServerRestTest#testSupervisorOverrideRequiresAcceptedSession`, `LivenessServerWebSocketTest#testMissingTokenRejectedInNonDemoMode`

### [P0-4] Lockout / Retries are Bypassable
- **Finding:** Lockout was keyed solely by frame `deviceId`, which `WebSocketHandler` populated with ephemeral `sessionId`. Reconnecting reset retry counts and lockout state.
- **Resolution:**
  - Keyed lockout and retry budgets by authenticated `clientIdentity` (token claim) and persistent `deviceId`, preserved in `DefaultLivenessEngine` across reconnections.
  - Recorded real client identity in audit events.
  - Refused new sessions with `MAX_RETRIES_EXCEEDED` once retry budget is exhausted.
- **Commit:** `feat(security): implement P0 anti-spoofing, audit signing, session auth, and lockout`
- **Tests:** `LivenessServerWebSocketTest#testPersistentLockoutAcrossSockets`

### [P0-5] Rejections Never Reach the User
- **Finding:** PAD-attack branches in `DefaultLivenessEngine` returned `LivenessDecision.rejected(...)` without notifying the session listener or triggering state change events, causing client UI to loop indefinitely without feedback.
- **Resolution:**
  - Routed all outcomes (acceptance, retry, challenge, PAD rejection) through unified `listener.onDecision(...)` and `listener.onStateChanged(...)`.
  - Included informative "Attempt N of M" messaging and reset progress on retry.
- **Commit:** `feat(security): implement P0 anti-spoofing, audit signing, session auth, and lockout`
- **Tests:** `DefaultLivenessEngineTest#testPadAttackDispatchesRejectionToListener`

### [P0-6] Tamper-Evident Audit Chain
- **Finding:** Audit event `details` map was excluded from SHA-256 hash calculation. First event previous hash was unvalidated, allowing front-truncation. Any attacker with write access could recompute valid unkeyed SHA-256 hashes. Verification treated all sessions as one chain, failing across sequential sessions.
- **Resolution:**
  - Implemented canonical sorted JSON serialization for `details` in `LivenessAuditEvent.java` hash computation.
  - Added strict check requiring initial event `previousHash` to equal `GENESIS_HASH`.
  - Added HMAC-SHA256 signature field and signing utility on final session events (`LIVENESS_AUDIT_KEY`).
  - Added session-aware verification in `AuditChainVerifier.verifySessions(...)`.
  - Added bounded LRU cache (1,000 sessions) and 10 MB rotation in `FileAuditSink.java`.
- **Commit:** `feat(security): implement P0 anti-spoofing, audit signing, session auth, and lockout`
- **Tests:** `LivenessAuditEventTest`, `AuditChainVerifierTest`

---

## Phase P1: Presentation Attack Detection (PAD) Quality

### [P1-1] Veto + Calibrated Fusion Instead of a Plain Average
- **Finding:** Simple weighted average allowed severe multi-vector attacks (e.g. failing moire, specular, border, timing) to register ~0.50 and evade detection when other signals were high. Post-challenge completion accepted without checking blended scores against policy thresholds. No 3D mask attack classification existed.
- **Resolution:**
  - Created versioned logistic regression model `fusion_model_v1.json` with calibrated feature weights and intercept.
  - Implemented pure-Java `LogisticFusionModel.java` evaluating logistic sigmoid $\sigma(w_0 + \sum w_i x_i)$ and multi-vector hard-veto rules ($\ge 2$ screen failures $\implies$ `SCREEN_REPLAY`; zero-motion $\implies$ `PRINT_ATTACK`; frozen stream $\implies$ `VIDEO_INJECTION`; $\ge 3$ failures $\implies$ `UNKNOWN_ATTACK`).
  - Added `computeMask3DScore` in `PassiveAnalyzer.java` and `PadClassification.MASK_3D` detecting synthetic silicone/latex pigment uniformity and cutout boundary gradients.
  - Updated `DefaultLivenessEngine.java` to cache challenge frames, re-evaluate PAD over challenge frames, and assert `blendedScore >= policy.passiveThreshold()`.
- **Commit:** `feat(pad): implement P1 logistic fusion, hard veto, onnx module, and active challenge hardening`
- **Tests:** `PassiveAnalyzerTest#testHardVetoScreenAttack`, `PassiveAnalyzerTest#testStaticPhotoAttack`

### [P1-2] Signal Realignment with Documented Specifications
- **Finding:**
  - Micro-motion excluded eyelids and lacked similarity-transform alignment.
  - Timing checked only frozen checksums, ignoring microsecond bursts, clock drift, and synthetic timers.
  - Moire was destroyed by downscaling 400px JPEG q0.7 to 64x64 before FFT.
  - Border claimed Hough line transform in documentation but used a simple gradient check.
- **Resolution:**
  - Refined `computeMicroMotionScore` to calculate non-rigid landmark jitter residual after fitting a Procrustes-style similarity transform plus palpebral fissure EAR micro-variance.
  - Refined `computeTimingIntegrityScore` with inter-frame arrival variance, microsecond burst rejection ($<3\text{ ms}$), prolonged stall detection ($>1.5\text{ s}$), client timestamp monotonicity, and clock drift bounds ($>2\text{ s}$).
  - Updated `ImageOps.java` to extract native-resolution $64\times 64$ patches without downscaling before 2D FFT, preserving screen-grid frequencies. Web client sends 640x480 at $q=0.85$.
  - Implemented Radon/Hough orthogonal collinear edge accumulator in `computeBorderScore` detecting physical bezels and paper edges.
- **Commit:** `feat(pad): implement P1 logistic fusion, hard veto, onnx module, and active challenge hardening`
- **Tests:** `PassiveAnalyzerTest#testSyntheticBurstTimingDetection`, `ImageOpsTest`

### [P1-3] Real Neural PAD Optional Module (`liveness-onnx`)
- **Finding:** Engine advertised `+onnx` in version string without executing inference models, and no real inference code existed in repository.
- **Resolution:**
  - Added Maven module `liveness-onnx` containing `UltraFaceDetector.java` (UltraFace-RFB-320 ONNX), `MiniFasNetPadAnalyzer.java` (multi-scale crop neural PAD), and `FaceEmbeddingService.java` (cosine facial embedding similarity).
  - Created `scripts/download_models.sh` and `scripts/download_models.ps1` with SHA-256 integrity verification.
  - Configured graceful degradation when ONNX model files are absent.
- **Commit:** `feat(pad): implement P1 logistic fusion, hard veto, onnx module, and active challenge hardening`
- **Tests:** `OnnxModulesTest`

### [P1-4] Stronger Active Challenge & Color Flash
- **Finding:** Challenge nonces were never validated; turn/nod passed on a single frame crossing threshold; no identity consistency check across challenge window.
- **Resolution:**
  - Added random `challengeToken` nonce issuing per challenge; web client echoes it on every frame; server rejects frames with mismatched tokens.
  - Enforced frame sequence monotonicity and timestamp monotonicity in `WebSocketHandler.java`.
  - Added hold duration and return-to-center tracking in `ChallengeVerifier.java`.
  - Added `COLOR_FLASH` challenge type with photometric illumination reflection verification in `ChallengeVerifier.java` and animated color flash in `app.js`.
- **Commit:** `feat(pad): implement P1 logistic fusion, hard veto, onnx module, and active challenge hardening`
- **Tests:** `ChallengeVerifierTest`

### [P1-5] Injection Hardening
- **Finding:** Browser injection tools and virtual cameras could bypass baseline heuristics.
- **Resolution:**
  - Added virtual camera inspection in `app.js` checking `MediaStreamTrack.label` for virtual camera drivers (`obs`, `virtual`, `manycam`, `v4l2loopback`).
  - Added Jetty WebSocket text message limit configuration (1 MB).
  - Aligned repository license to `Apache License, Version 2.0`.
- **Commit:** `feat(pad): implement P1 logistic fusion, hard veto, onnx module, and active challenge hardening`
- **Tests:** `LivenessServerWebSocketTest`

---

## Phase P2: Evidence, Benchmarks & Hardening

### [P2-1] ISO/IEC 30107-3 Benchmark with Measured Numbers
- **Finding:** Prior evaluator was passive-only, lacked active challenge integration, and had no standard compliance metrics (APCER, BPCER, DET curve, Clopper-Pearson CIs, or latency distribution).
- **Resolution:**
  - Upgraded `Evaluator.java` to compute ISO/IEC 30107-3 metrics across presentation attack species: APCER per category, BPCER, BPCER at APCER $\le 5\%$ and $\le 1\%$, complete DET curve data, exact Clopper-Pearson 95% confidence intervals, and p50/p95 latency percentiles.
  - Upgraded `collect.html` to capture synchronized multi-frame JPEG sequences, MediaPipe landmark sidecars, and `timeline.json` challenge tracking.
  - Implemented procedural benchmark dataset generator `GenerateBenchmarkDataset.java` producing 135 calibrated presentation sequences (30 genuine, 30 print, 30 phone replay, 30 tablet replay, 15 mask) with realistic 3D facial shading and physiological non-rigid tremor (0.0025 px) with zero raw human biometric data retained.
  - Output report committed at `docs/BENCHMARK_REPORT.md` and dataset documentation at `liveness-eval/datasets/README.md`.
- **Commit:** `feat(eval): benchmark ISO/IEC 30107-3 metrics, adversarial tests, and jacoco gate`
- **Tests:** `EvaluatorTest`, `GenerateBenchmarkDataset`

### [P2-2] Adversarial & Property Testing, Coverage Gate
- **Finding:** Test coverage was thin in core engine and analyzers, missing adversarial vectors such as forged landmarks, skin-blob fallbacks, and chain truncation. No automated coverage enforcement existed.
- **Resolution:**
  - Added adversarial unit tests in `DefaultLivenessEngineTest.java`:
    - `testForgedLandmarksMismatchDetected`: forged client landmarks mismatched with server face detection generate `LANDMARK_MISMATCH` audit and generic user error.
    - `testNoLandmarkFallbackReturnsNoFace`: skin-coloured blob without landmarks yields `NO_FACE_DETECTED` without landmark fabrication.
    - `testPersistentLockoutAcrossReconnects`: lockout persists across reconnects and new sockets for the same authenticated identity.
    - `testReplayDetectionInStream`: frozen identical frame buffer sequences trigger video injection / timing attack rejection.
  - Added randomized property-based audit verification in `AuditChainVerifierTest#testAuditChainPropertyTesting` testing chains of length 2..12 and proving any single-field tamper in any event breaks the chain at that exact index.
  - Added `jacoco-maven-plugin` (0.8.12) to `liveness-core` enforcing a strict $\ge 70\%$ instruction coverage gate on `mvn verify`.
- **Commit:** `feat(eval): benchmark ISO/IEC 30107-3 metrics, adversarial tests, and jacoco gate`
- **Tests:** `DefaultLivenessEngineTest`, `AuditChainVerifierTest`, `PassiveAnalyzerTest`

### [P2-3] Production CI & Container Hardening
- **Finding:** CI only ran basic compile and test without static security analysis, container builds, or evaluation benchmarks. Dockerfile had invalid source copy paths (`liveness-device-mock`), missing runtime `curl`, and defaulted `LIVENESS_DEMO=true`.
- **Resolution:**
  - Updated `.github/workflows/ci.yml` to include SpotBugs check, OWASP dependency-check, benchmark report artifact generation/upload, JaCoCo report upload, and Docker container build validation.
  - Fixed `Dockerfile` copy paths (`liveness-device-mock/src` and `liveness-onnx`), installed `curl` in runtime stage for healthcheck, defaulted `LIVENESS_DEMO=false`, and created `.dockerignore`.
  - Dropped unused `liveness-device-mock` dependency from `liveness-server/pom.xml`.
- **Commit:** `feat(eval): benchmark ISO/IEC 30107-3 metrics, adversarial tests, and jacoco gate`
- **Tests:** `mvn verify` across all modules

---

## Phase P3: Demo & Packaging, Hardening, and Docs Honesty

### [P3-1] Judge Mode UI, Split View & Red Team Replay Gallery
- **Finding:** Diagnostic WS messages only sent static weights without live signal scores. Judges had no way to view internal engine state side-by-side with user view or test specific attacks interactively.
- **Resolution:**
  - Implemented `LivenessEngine.getSessionDiagnostics(session)` in `DefaultLivenessEngine.java` exposing real-time per-signal heuristic scores (`microMotion`, `moire`, `specular`, `texture`, `border`, `timing`, `consistency`, `mask3d`), liveness score, attack score, and attack classification.
  - Updated `WebSocketHandler.java` to measure frame processing latency in nanoseconds and stream live telemetry whenever Judge Mode or `--diagnostic` is active.
  - Implemented side-by-side "Split View" mode in `index.html` and `app.js` separating "What the Attacker Sees" (clean video, generic status, zero leakage) from "What the Audit Knows" (real-time telemetry radar, latency badge, veto status).
  - Built an interactive **Red Team Lab** with four standardized attack simulators (Print Attack, Mobile Screen Replay, 3D Mask, and Forged Landmark Injection) demonstrating real-time blocking and evidence generation.
- **Commit:** `feat(p3): judge mode split view, audit verifier cli, offline mediapipe, mosip receipt, docs honesty`
- **Tests:** `WebSocketHandlerTest`, `DefaultLivenessEngineTest`

### [P3-2] Honest Tamper Demo & Standalone AuditVerifierCli
- **Finding:** Tamper button misleadingly appeared to edit server state in place rather than demonstrating audit verification failure on an altered copy. No offline verification tool existed for auditors.
- **Resolution:**
  - Relabeled browser button to *"Simulate Edit on Local Log Copy"* with clear explanatory tooltips.
  - Implemented standalone command-line tool `io.mosip.liveness.core.audit.AuditVerifierCli.java` in `liveness-core` (pure Java 17, zero external runtime dependencies) that parses `audit.jsonl` files, verifies SHA-256 hash chaining, checks genesis root, verifies canonical details, and validates terminal HMAC-SHA256 signatures.
- **Commit:** `feat(p3): judge mode split view, audit verifier cli, offline mediapipe, mosip receipt, docs honesty`
- **Tests:** `AuditVerifierCliTest`

### [P3-3] Offline MediaPipe Vendoring & HTTPS / TLS Architecture
- **Finding:** Browser client loaded MediaPipe WebAssembly and task models dynamically from jsDelivr and Google Cloud Storage at runtime, breaking offline operation and data-sovereignty mandates. Mobile browsers failed `getUserMedia` over local Wi-Fi without HTTPS.
- **Resolution:**
  - Downloaded and vendored MediaPipe Tasks Vision bundle, WebAssembly runtimes (`vision_wasm_internal.*`, `vision_wasm_nosimd_internal.*`), and `face_landmarker.task` directly into `liveness-server/src/main/resources/web/vendor/mediapipe/`.
  - Updated `app.js` to load from local offline vendored assets first, gracefully falling back to CDN only if local files are missing.
  - Added `scripts/download_mediapipe.sh` and `scripts/download_mediapipe.ps1` for reproducible asset downloads.
  - Added `Caddyfile` and `docker-compose.yml` configuring automatic internal TLS on port 8443 reverse-proxying to `liveness-server:8080`, enabling mobile webcam testing across local LANs.
- **Commit:** `feat(p3): judge mode split view, audit verifier cli, offline mediapipe, mosip receipt, docs honesty`
- **Tests:** Verified offline loading in web client

### [P3-4] MOSIP Integration Story & Signed JWS Liveness Receipts
- **Finding:** The accepted "best compliant frame" never left the engine, and no integration receipt or MOSIP biometric SDK adapter existed showing how Registration Client or IDA would consume results.
- **Resolution:**
  - Implemented `MosipLivenessReceipt.java` generating RFC 7515 compliant JWS compact tokens signed with HMAC-SHA256, cryptographically binding `sessionId`, `nonce`, `decision` (`ACCEPTED`), `workflow`, `policyHash`, `bestFrameSha256`, and expiration.
  - Implemented `MosipBiometricSdkAdapter.java` demonstrating how MOSIP Registration Client / IDA validates presented liveness assertion receipts against expected nonces and workflows before accepting biometric packets.
- **Commit:** `feat(p3): judge mode split view, audit verifier cli, offline mediapipe, mosip receipt, docs honesty`
- **Tests:** `MosipLivenessReceiptTest`, `MosipBiometricSdkAdapterTest`

### [P3-5] Accessibility, Tamil i18n & SpeechSynthesis Voice Guidance
- **Finding:** Progress bar labels, policy drawers, and audit headers were only partially translated into Tamil. No spoken audio guidance existed for low-vision users.
- **Resolution:**
  - Extended `LocalizationService.java` and `app.js` with comprehensive Tamil translations for progress bar, policy parameters, and audit table headers.
  - Integrated Web `SpeechSynthesis` API in `app.js` providing real-time voice prompts in Tamil (`ta-IN`) and English (`en-US`) for positioning, active challenges, and decision announcements.
  - Added High-Contrast Mode toggle (`🌓 Contrast`) and pure-black/high-visibility CSS tokens.
  - Added `aria-live="polite"` and `aria-live="assertive"` regions for screen-reader compatibility.
- **Commit:** `feat(p3): judge mode split view, audit verifier cli, offline mediapipe, mosip receipt, docs honesty`
- **Tests:** Verified localization strings in `LocalizationServiceTest`

### [P3-6] Engine Hardening, RAM Cleanup & Docs Honesty Pass
- **Finding:**
  - `ImageIO.read` decompressed incoming images before dimension checks (decompression bomb vulnerability).
  - Volatile frame buffers (`jpegBytes`, `int[] pixels`) lingered in RAM until garbage collection.
  - Engine sessions and best compliant frames were never evicted after terminal decisions.
  - Documentation, CODING_STANDARDS, and Javadocs claimed face area 0.15–0.75 and Laplacian variance $\ge 80$, whereas code enforced `0.08..0.75` and `35.0`.
  - Repository claimed "production-ready" despite heuristic limitations.
- **Resolution:**
  - Implemented `ImageReader` header dimension parsing before raster decompression, dropping oversized frames ($>1280\times 1280$).
  - Added explicit zeroing (`Arrays.fill`) for volatile pixel buffers and byte arrays immediately after frame processing in `WebSocketHandler.java`.
  - Added `finishSession(session)` to `LivenessEngine` and `DefaultLivenessEngine` wiping `bestCompliantFrame` and evicting session context upon decision emission or socket closure.
  - Aligned face area ratio (`0.08..0.75`) and Laplacian variance ($\ge 35.0$) across `README.md`, `CODING_STANDARDS.md`, and `QualityEvaluator.java`.
  - Re-scoped project documentation to "Reference Implementation & Prototype".
  - Created `THREAT_MODEL.md` and `ARCHITECTURE.md` with complete Mermaid sequence diagrams.
  - Updated `DEMO.md` with 90-second pitch script and 3-minute Judge Mode walkthrough.
- **Commit:** `feat(p3): judge mode split view, audit verifier cli, offline mediapipe, mosip receipt, docs honesty`
- **Tests:** `mvn clean verify` green across all 7 modules

---

## Phase P4: Production Hardening, Branded 404, Mobile UX & Tooling

### [P4-1] Accessible Branded 404 Handler & Convenience Redirects
- **Finding:** Unmapped paths yielded default Jetty 404 plaintext or uncaught errors. Broken asset links could leak server stack traces or return HTML to script loaders causing syntax errors. Missing convenience redirects for `/health` and `/collect`.
- **Resolution:**
  - Implemented custom `app.error(HttpStatus.NOT_FOUND, ...)` in `LivenessServerApp.java`.
  - Serves branded, responsive `404.html` with zero-leakage design, return-to-safety actions, and dynamic year.
  - Returns structured RFC-compliant JSON (`{"error": "Not Found", "status": 404, "path": "..."}`) for `/api/*` routes.
  - Preserves non-HTML plain responses for asset files (`.js`, `.css`, etc.) preventing script MIME type parsing errors.
  - Added seamless 302 redirects: `/health` $\to$ `/api/health`, `/collect` $\to$ `/collect.html`.
- **Tests:** `LivenessServerRestTest#custom404HtmlHandler`, `LivenessServerRestTest#custom404ApiJsonHandler`, `LivenessServerRestTest#custom404StaticAssetHandler`, `LivenessServerRestTest#convenienceRedirects`

### [P4-2] Mobile Navigation & Minimum Touch Targets
- **Finding:** Header controls overflowed on mobile viewports (<768px), making workflow selection, language toggle, and Judge Mode inaccessible on phones.
- **Resolution:**
  - Added accessible hamburger menu toggle button (`mobileMenuBtn`) with ARIA expanded state, keyboard navigation (`Esc` to dismiss), and backdrop blur.
  - Enforced $\ge 44\times 44\text{px}$ touch target sizes on buttons and select inputs across mobile breakpoints ($340\text{px}$, $480\text{px}$, $768\text{px}$).
- **Tests:** Responsive layout verification in browser client

### [P4-3] Accessible Modal Dialogs & Toast Notifications
- **Finding:** Browser `prompt()` and `alert()` modals blocked the main thread and violated accessibility standards.
- **Resolution:**
  - Replaced native `prompt()` for Judge Mode with accessible HTML5 modal (`tokenModalOverlay`), handling autofocus, Enter/Esc keys, and inline validation errors.
  - Replaced native `alert()` with non-blocking, accessible toast notifications (`showToast()`) with auto-dismiss and screen-reader `role="status"` announcements.
- **Tests:** UI verification in `app.js`

### [P4-4] Dataset Collector Validation & Error Banners
- **Finding:** `collect.html` lacked input validation on frame counts and failed silently without actionable user guidance when camera permissions were denied.
- **Resolution:**
  - Added input validation for frame capture count ($5\le N\le 30$) with inline error messaging.
  - Added camera permission error banner (`collectCameraError`) displaying specific browser permission remediation instructions.
- **Tests:** `collect.html` client verification

### [P4-5] Native Maven Wrapper (`mvnw` / `mvnw.cmd`)
- **Finding:** Developers without Maven pre-installed in global PATH encountered `mvn: command not found` execution failures.
- **Resolution:**
  - Vendored Apache Maven 3.9.9 wrapper (`mvnw`, `mvnw.cmd`, `.mvn/wrapper/maven-wrapper.properties`) providing zero-configuration out-of-the-box building and testing.
- **Tests:** `.\mvnw.cmd test` passes across all modules


