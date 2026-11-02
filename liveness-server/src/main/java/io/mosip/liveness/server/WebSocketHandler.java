package io.mosip.liveness.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.websocket.WsCloseContext;
import io.javalin.websocket.WsConnectContext;
import io.javalin.websocket.WsErrorContext;
import io.javalin.websocket.WsMessageContext;
import io.mosip.liveness.api.challenge.Challenge;
import io.mosip.liveness.api.decision.DecisionType;
import io.mosip.liveness.api.decision.LivenessDecision;
import io.mosip.liveness.api.engine.LivenessListener;
import io.mosip.liveness.api.engine.LivenessSession;
import io.mosip.liveness.api.error.LivenessError;
import io.mosip.liveness.api.frame.FaceFrame;
import io.mosip.liveness.api.frame.PixelFormat;
import io.mosip.liveness.api.policy.LivenessPolicy;
import io.mosip.liveness.api.policy.WorkflowType;
import io.mosip.liveness.api.quality.FaceQuality;
import io.mosip.liveness.api.quality.Point2D;
import io.mosip.liveness.api.quality.QualityFailureReason;
import io.mosip.liveness.core.analyzer.ClientLandmarkAnalyzer;
import io.mosip.liveness.core.engine.DefaultLivenessEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Handles WebSocket sessions for real-time video frame streaming and liveness detection.
 */
public class WebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(WebSocketHandler.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    // 15 FPS rate limit: minimum 66.6 ms between frames
    private static final long MIN_FRAME_INTERVAL_NANOS = 66_000_000L;
    private static final int MAX_FRAME_BYTES = 1_048_576; // 1 MB
    private static final int MAX_DIMENSION = 1280;

    private final DefaultLivenessEngine engine;
    private final ServerConfig config;
    private final SessionTokenService tokenService;
    private final Map<String, SocketSessionState> sessions = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> ipConnections = new ConcurrentHashMap<>();

    public WebSocketHandler(DefaultLivenessEngine engine, ServerConfig config) {
        this.engine = engine;
        this.config = config;
        this.tokenService = new SessionTokenService(config.sessionSecret());
    }

    public int getActiveSessionCount() {
        return sessions.size();
    }

    private static class SocketSessionState {
        final WsConnectContext ws;
        final String lang;
        final WorkflowType workflow;
        final String clientIdentity;
        final String deviceId;
        final boolean judgeMode;
        final String clientIp;
        LivenessSession session;
        long lastFrameNanos = 0L;
        long lastActivityMillis = System.currentTimeMillis();
        long totalBytesReceived = 0L;
        long lastSeq = -1L;
        long lastTsMs = 0L;
        long lastFrameLatencyMs = 0L;

        SocketSessionState(WsConnectContext ws, String lang, WorkflowType workflow,
                           String clientIdentity, String deviceId, boolean judgeMode, String clientIp) {
            this.ws = ws;
            this.lang = lang != null ? lang : "en";
            this.workflow = workflow != null ? workflow : WorkflowType.RESIDENT_AUTH;
            this.clientIdentity = clientIdentity;
            this.deviceId = deviceId;
            this.judgeMode = judgeMode;
            this.clientIp = clientIp;
        }
    }

    public void onConnect(WsConnectContext ctx) {
        String clientIp = resolveClientIp(ctx);

        // 1. Check Origin allow-list
        String origin = ctx.header("Origin");
        if (!isOriginAllowed(origin, config.allowedOrigins())) {
            log.warn("WebSocket rejected: Forbidden Origin [{}] from IP {}", origin, clientIp);
            ctx.closeSession(1008, "Origin not allowed");
            return;
        }

        // 2. Check per-IP connection cap
        int count = ipConnections.computeIfAbsent(clientIp, k -> new AtomicInteger(0)).incrementAndGet();
        if (count > config.maxConnectionsPerIp()) {
            ipConnections.get(clientIp).decrementAndGet();
            log.warn("WebSocket rejected: Per-IP connection cap exceeded for IP {}", clientIp);
            ctx.closeSession(1008, "Too many connections from IP");
            return;
        }

        // 3. Authenticate session token / demo fallback
        String tokenParam = ctx.queryParam("token");
        SessionTokenService.SessionToken verifiedToken = tokenService.verifyToken(tokenParam);

        String sessionId;
        WorkflowType workflow;
        String clientIdentity;

        if (verifiedToken.valid()) {
            sessionId = verifiedToken.sessionId();
            workflow = verifiedToken.workflow();
            clientIdentity = verifiedToken.clientIdentity();
        } else if (config.demoMode()) {
            // Demo mode fallback: allow unauthenticated connects with query params
            sessionId = java.util.UUID.randomUUID().toString();
            String workflowParam = ctx.queryParam("workflow");
            workflow = WorkflowType.RESIDENT_AUTH;
            if (workflowParam != null) {
                try {
                    workflow = WorkflowType.valueOf(workflowParam.trim().toUpperCase());
                } catch (IllegalArgumentException ignored) {}
            }
            clientIdentity = clientIp;
        } else {
            ipConnections.get(clientIp).decrementAndGet();
            log.warn("WebSocket rejected: Missing or invalid session token from IP {}", clientIp);
            ctx.closeSession(1008, "Valid session token required. Request via POST /api/v1/sessions");
            return;
        }

        String lang = ctx.queryParam("lang");
        String adminTokenParam = ctx.queryParam("adminToken");
        boolean judgeMode = config.diagnosticMode() || constantTimeEquals(adminTokenParam, config.adminToken());

        String deviceId = ctx.queryParam("deviceId");
        if (deviceId == null || deviceId.isBlank()) {
            deviceId = clientIdentity;
        }

        SocketSessionState state = new SocketSessionState(ctx, lang, workflow, clientIdentity, deviceId, judgeMode, clientIp);
        LivenessPolicy policy = resolvePolicy(workflow, config.demoMode());

        LivenessListener listener = createListener(state);
        try {
            LivenessSession session = engine.startSession(sessionId, workflow, policy, listener, clientIdentity);
            state.session = session;
            sessions.put(ctx.sessionId(), state);

            log.info("WebSocket connected: socketId={}, livenessSessionId={}, workflow={}, clientIdentity={}, judgeMode={}",
                    ctx.sessionId(), session.getSessionId(), workflow, clientIdentity, judgeMode);
        } catch (Exception e) {
            ipConnections.get(clientIp).decrementAndGet();
            log.warn("Refused session start for {}: {}", clientIdentity, e.getMessage());
            ctx.closeSession(1008, e.getMessage());
        }
    }

    public void onMessage(WsMessageContext ctx) {
        SocketSessionState state = sessions.get(ctx.sessionId());
        if (state == null || state.session == null || state.session.isClosed()) {
            return;
        }
        state.lastActivityMillis = System.currentTimeMillis();

        String message = ctx.message();
        if (message == null || message.isBlank()) return;

        try {
            JsonNode root = mapper.readTree(message);
            String type = root.path("type").asText();

            if ("cancel".equalsIgnoreCase(type)) {
                log.info("Client requested session cancel: socketId={}", ctx.sessionId());
                engine.cancelSession(state.session);
                ctx.closeSession();
                sessions.remove(ctx.sessionId());
                return;
            }

            if ("frame".equalsIgnoreCase(type)) {
                handleFrameMessage(state, root);
            }
        } catch (Exception e) {
            log.error("Error processing WebSocket message for socket {}", ctx.sessionId(), e);
            sendJson(state.ws, Map.of(
                    "type", "error",
                    "code", LivenessError.ENGINE_ERROR.getErrorCode(),
                    "message", LocalizationService.translate("DECISION_ERROR", "Internal error processing frame", state.lang)
            ));
        }
    }

    private void handleFrameMessage(SocketSessionState state, JsonNode root) throws IOException {
        long nowNanos = System.nanoTime();
        if (nowNanos - state.lastFrameNanos < MIN_FRAME_INTERVAL_NANOS) {
            // Drop frame to enforce 15 FPS rate limit
            return;
        }
        state.lastFrameNanos = nowNanos;

        String b64 = root.path("jpegB64").asText();
        if (b64.isEmpty()) return;

        // Strip data:image/jpeg;base64, prefix if present
        int commaIdx = b64.indexOf(',');
        if (commaIdx >= 0) {
            b64 = b64.substring(commaIdx + 1);
        }

        byte[] jpegBytes = Base64.getDecoder().decode(b64);

        // Session byte cap check
        state.totalBytesReceived += jpegBytes.length;
        if (state.totalBytesReceived > config.maxSessionBytes()) {
            log.warn("Session {} exceeded byte quota ({} bytes)", state.session.getSessionId(), state.totalBytesReceived);
            sendJson(state.ws, Map.of(
                    "type", "error",
                    "code", LivenessError.INVALID_FRAME_DATA.getErrorCode(),
                    "message", "Session byte cap exceeded."
            ));
            state.ws.closeSession(1008, "Byte cap exceeded");
            return;
        }

        if (jpegBytes.length > MAX_FRAME_BYTES) {
            sendJson(state.ws, Map.of(
                    "type", "error",
                    "code", LivenessError.INVALID_FRAME_DATA.getErrorCode(),
                    "message", "Frame exceeds maximum size (1 MB)"
            ));
            return;
        }

        // P3-6: Inspect dimensions before full decompression to mitigate decompression bomb
        int w = 0;
        int h = 0;
        Iterator<ImageReader> readers = ImageIO.getImageReadersByFormatName("jpeg");
        if (readers.hasNext()) {
            ImageReader reader = readers.next();
            try (ImageInputStream iis = ImageIO.createImageInputStream(new ByteArrayInputStream(jpegBytes))) {
                reader.setInput(iis, true);
                w = reader.getWidth(0);
                h = reader.getHeight(0);
            } catch (Exception ignored) {
            } finally {
                reader.dispose();
            }
        }

        if (w > MAX_DIMENSION || h > MAX_DIMENSION || w <= 0 || h <= 0) {
            sendJson(state.ws, Map.of(
                    "type", "error",
                    "code", LivenessError.INVALID_FRAME_DATA.getErrorCode(),
                    "message", "Frame dimensions out of bounds"
            ));
            return;
        }

        BufferedImage img = ImageIO.read(new ByteArrayInputStream(jpegBytes));
        if (img == null) {
            return;
        }

        // Convert BufferedImage to RGB byte array
        byte[] rgbBytes = new byte[w * h * 3];
        int[] pixels = img.getRGB(0, 0, w, h, null, 0, w);
        for (int i = 0; i < pixels.length; i++) {
            int p = pixels[i];
            rgbBytes[i * 3] = (byte) ((p >> 16) & 0xFF);
            rgbBytes[i * 3 + 1] = (byte) ((p >> 8) & 0xFF);
            rgbBytes[i * 3 + 2] = (byte) (p & 0xFF);
        }

        long seq = root.path("seq").asLong(-1L);
        long tsMs = root.path("tsMs").asLong(0L);

        // P1-4: Reject stale/duplicate seq and non-monotonic tsMs
        if (seq >= 0 && state.lastSeq >= 0 && seq <= state.lastSeq) {
            log.warn("Dropped stale/duplicate frame sequence {} (lastSeq={})", seq, state.lastSeq);
            return;
        }
        if (seq >= 0) {
            state.lastSeq = seq;
        }

        if (tsMs > 0 && state.lastTsMs > 0 && tsMs < state.lastTsMs) {
            log.warn("Dropped non-monotonic frame timestamp {} ms (lastTsMs={})", tsMs, state.lastTsMs);
            return;
        }
        if (tsMs > 0) {
            state.lastTsMs = tsMs;
        }

        // P1-4: Challenge token echo verification
        if (state.session != null && state.session.getCurrentChallenge() != null) {
            Challenge activeCh = state.session.getCurrentChallenge();
            String tokenVal = root.path("challengeToken").asText();
            String echoToken = !tokenVal.isEmpty() ? tokenVal : root.path("challengeId").asText();
            if (!echoToken.isEmpty() && !activeCh.nonce().equals(echoToken) && !activeCh.challengeId().equals(echoToken)) {
                log.warn("Frame rejected during active challenge: token '{}' does not match active challenge '{}'",
                        echoToken, activeCh.challengeId());
                return;
            }
        }

        // Parse landmarks if provided
        List<Point2D> points = parseLandmarks(root.path("landmarks"));
        if (!points.isEmpty()) {
            if (engine.getFaceAnalyzer() instanceof ClientLandmarkAnalyzer clientAnalyzer) {
                clientAnalyzer.pushLandmarks(state.session.getSessionId(), points, 0.99, 1);
            }
        }

        FaceFrame frame = FaceFrame.wrap(
                rgbBytes,
                w,
                h,
                PixelFormat.RGB_888,
                nowNanos,
                seq,
                state.deviceId,
                0
        );

        long t0 = System.nanoTime();
        try {
            engine.processFrame(state.session, frame);
            state.lastFrameLatencyMs = (System.nanoTime() - t0) / 1_000_000L;
            if (config.diagnosticMode() || state.judgeMode) {
                sendDiagnosticIfAvailable(state);
            }
        } finally {
            if (!frame.isWiped()) {
                frame.wipe();
            }
            // P3-6: Zero intermediate volatile buffers
            Arrays.fill(pixels, 0);
            Arrays.fill(jpegBytes, (byte) 0);
        }
    }

    private List<Point2D> parseLandmarks(JsonNode lmNode) {
        if (lmNode == null || !lmNode.isArray()) return List.of();
        List<Point2D> result = new ArrayList<>(lmNode.size());
        for (JsonNode pt : lmNode) {
            double x, y;
            if (pt.isArray() && pt.size() >= 2) {
                x = pt.get(0).asDouble();
                y = pt.get(1).asDouble();
            } else if (pt.isObject() && pt.has("x") && pt.has("y")) {
                x = pt.get("x").asDouble();
                y = pt.get("y").asDouble();
            } else {
                continue;
            }
            result.add(Point2D.of((float) x, (float) y));
        }
        return result;
    }

    private void sendDiagnosticIfAvailable(SocketSessionState state) {
        Map<String, Object> diag = new LinkedHashMap<>();
        diag.put("type", "diagnostic");
        diag.put("sessionId", state.session.getSessionId());
        diag.put("workflow", state.workflow.name());
        diag.put("retryCount", state.session.getRetryCount());
        diag.put("activeChallenge", state.session.getCurrentChallenge() != null ? state.session.getCurrentChallenge().type().name() : null);
        diag.put("latencyMs", state.lastFrameLatencyMs);

        // Fetch live per-signal heuristics and real-time PAD evaluation from engine
        Map<String, Object> engineDiag = engine.getSessionDiagnostics(state.session);
        if (!engineDiag.isEmpty()) {
            diag.putAll(engineDiag);
        } else {
            Map<String, Object> weights = new LinkedHashMap<>();
            weights.put("microMotion", 0.15);
            weights.put("texture", 0.20);
            weights.put("specular", 0.15);
            weights.put("moire", 0.15);
            weights.put("colorDistribution", 0.15);
            weights.put("borderAnomaly", 0.10);
            weights.put("timingJitter", 0.10);
            diag.put("weights", weights);
        }

        sendJson(state.ws, diag);
    }

    public void onClose(WsCloseContext ctx) {
        SocketSessionState state = sessions.remove(ctx.sessionId());
        if (state != null) {
            AtomicInteger count = ipConnections.get(state.clientIp);
            if (count != null) {
                count.decrementAndGet();
            }
            if (state.session != null && !state.session.isClosed()) {
                engine.finishSession(state.session);
            }
        }
        log.info("WebSocket closed: socketId={}", ctx.sessionId());
    }

    public void onError(WsErrorContext ctx) {
        log.warn("WebSocket error for socket {}: {}", ctx.sessionId(), ctx.error() != null ? ctx.error().getMessage() : "unknown");
    }

    private LivenessListener createListener(SocketSessionState state) {
        return new LivenessListener() {
            @Override
            public void onStateChanged(LivenessSession session, String stateName, String prompt) {
                String localizedPrompt = LocalizationService.translate("STATE_" + stateName, prompt, state.lang);
                sendJson(state.ws, Map.of(
                        "type", "state",
                        "state", stateName,
                        "prompt", localizedPrompt
                ));
            }

            @Override
            public void onQualityFeedback(LivenessSession session, FaceQuality quality, String guidanceMessage) {
                QualityFailureReason primaryReason = quality.qualityFailures().isEmpty()
                        ? null
                        : quality.qualityFailures().iterator().next();
                String localizedGuidance = primaryReason != null
                        ? LocalizationService.getQualityGuidance(primaryReason, state.lang)
                        : (guidanceMessage != null ? guidanceMessage : "");

                Map<String, Object> metrics = new LinkedHashMap<>();
                metrics.put("blur", quality.blurScore());
                metrics.put("yaw", quality.poseYaw());
                metrics.put("pitch", quality.posePitch());
                metrics.put("roll", quality.poseRoll());
                metrics.put("ear", (quality.eyeOpenLeft() + quality.eyeOpenRight()) / 2.0);
                metrics.put("mar", quality.mouthOpen());
                metrics.put("luma", quality.brightnessScore());
                metrics.put("faceAreaRatio", quality.faceSizeRatio());
                metrics.put("isCompliant", quality.isCompliant());

                sendJson(state.ws, Map.of(
                        "type", "quality",
                        "guidance", localizedGuidance,
                        "metrics", metrics
                ));
            }

            @Override
            public void onPassiveProgress(LivenessSession session, int collectedFrames, int totalFramesRequired) {
                sendJson(state.ws, Map.of(
                        "type", "progress",
                        "collected", collectedFrames,
                        "window", totalFramesRequired
                ));
            }

            @Override
            public void onChallengeIssued(LivenessSession session, Challenge challenge) {
                String prompt = LocalizationService.getChallengePrompt(challenge.type(), state.lang);
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("type", "challenge");
                payload.put("challengeId", challenge.challengeId());
                payload.put("challengeType", challenge.type().name());
                payload.put("prompt", prompt);
                payload.put("timeoutMs", challenge.timeoutMillis());
                payload.put("challengeToken", challenge.nonce());
                sendJson(state.ws, payload);
            }

            @Override
            public void onDecision(LivenessSession session, LivenessDecision decision) {
                // Rule P0-2: Public WS payload = decision enum + generic message only. No score, no PAD info.
                String userMsg;
                if (decision.decisionType() == DecisionType.REJECTED) {
                    userMsg = LocalizationService.translate("DECISION_REJECTED",
                            LivenessError.PAD_FAILURE.getDefaultUserMessage(), state.lang);
                } else if (decision.decisionType() == DecisionType.ACCEPTED) {
                    userMsg = LocalizationService.translate("DECISION_ACCEPTED",
                            "Face verification successful.", state.lang);
                } else if (decision.decisionType() == DecisionType.FAILED_MAX_RETRIES) {
                    userMsg = LocalizationService.translate("DECISION_FAILED_MAX_RETRIES",
                            LivenessError.MAX_RETRIES_EXCEEDED.getDefaultUserMessage(), state.lang);
                } else {
                    userMsg = LocalizationService.getDecisionMessage(decision.decisionType(), state.lang);
                }

                Map<String, Object> resp = new LinkedHashMap<>();
                resp.put("type", "decision");
                resp.put("decision", decision.decisionType().name());
                resp.put("userMessage", userMsg);

                // Anti-adversarial security gate: only judge mode unlocks internal metrics
                if (state.judgeMode) {
                    resp.put("score", decision.finalScore());
                    resp.put("sessionId", session.getSessionId());
                }

                sendJson(state.ws, resp);

                if (decision.decisionType() == DecisionType.ACCEPTED
                        || decision.decisionType() == DecisionType.REJECTED
                        || decision.decisionType() == DecisionType.FAILED_MAX_RETRIES) {
                    engine.finishSession(session);
                }
            }

            @Override
            public void onError(LivenessSession session, LivenessError error, String technicalDetails) {
                sendJson(state.ws, Map.of(
                        "type", "error",
                        "code", error.getErrorCode(),
                        "message", error.getDefaultUserMessage()
                ));
            }
        };
    }

    private void sendJson(WsConnectContext ws, Object payload) {
        if (ws == null) return;
        try {
            String json = mapper.writeValueAsString(payload);
            ws.send(json);
        } catch (Exception e) {
            log.warn("Failed to send WebSocket message: {}", e.getMessage());
        }
    }

    private static String resolveClientIp(WsConnectContext ctx) {
        String xff = ctx.header("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return (ctx.session != null && ctx.session.getRemoteAddress() != null)
                ? ctx.session.getRemoteAddress().toString()
                : "127.0.0.1";
    }

    private static boolean isOriginAllowed(String origin, List<String> allowedOrigins) {
        if (origin == null || origin.isBlank()) return true;
        if (allowedOrigins == null || allowedOrigins.isEmpty() || allowedOrigins.contains("*")) return true;
        for (String allowed : allowedOrigins) {
            if (origin.equalsIgnoreCase(allowed) || allowed.equals("*")) return true;
        }
        return false;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
        );
    }

    private static LivenessPolicy resolvePolicy(WorkflowType workflow, boolean demoMode) {
        LivenessPolicy base = switch (workflow) {
            case RESIDENT_ENROLLMENT -> LivenessPolicy.residentEnrollment();
            case RESIDENT_AUTH -> LivenessPolicy.residentAuth();
            case OPERATOR_AUTH -> LivenessPolicy.operatorAuth();
            case SUPERVISOR_AUTH -> LivenessPolicy.supervisorAuth();
        };

        if (demoMode) {
            return LivenessPolicy.builder()
                    .passiveThreshold(base.passiveThreshold())
                    .padThreshold(base.padThreshold())
                    .activeEnabled(base.activeEnabled())
                    .allowedChallengeTypes(base.allowedChallengeTypes())
                    .minChallenges(base.minChallenges())
                    .activeTimeoutSeconds(6)
                    .maxRetries(base.maxRetries())
                    .passiveWindowFrames(base.passiveWindowFrames())
                    .failureBehaviour(base.failureBehaviour())
                    .build();
        }
        return base;
    }
}
