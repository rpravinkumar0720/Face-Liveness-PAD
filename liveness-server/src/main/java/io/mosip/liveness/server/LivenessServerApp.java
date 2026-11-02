package io.mosip.liveness.server;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.HttpStatus;
import io.javalin.http.staticfiles.Location;
import io.mosip.liveness.api.audit.LivenessAuditEvent;
import io.mosip.liveness.api.decision.DecisionType;
import io.mosip.liveness.api.policy.LivenessPolicy;
import io.mosip.liveness.api.policy.WorkflowType;
import io.mosip.liveness.core.analyzer.ClientLandmarkAnalyzer;
import io.mosip.liveness.core.audit.AuditChainVerifier;
import io.mosip.liveness.core.audit.AuditSink;
import io.mosip.liveness.core.audit.FileAuditSink;
import io.mosip.liveness.core.audit.InMemoryAuditSink;
import io.mosip.liveness.core.challenge.ChallengeGenerator;
import io.mosip.liveness.core.engine.DefaultLivenessEngine;
import io.mosip.liveness.core.passive.PassiveAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Javalin application configuring REST endpoints, WebSocket streaming,
 * and static assets for the HTML5 webcam client.
 */
public class LivenessServerApp {

    private static final Logger log = LoggerFactory.getLogger(LivenessServerApp.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    private final ServerConfig config;
    private final DefaultLivenessEngine engine;
    private final InMemoryAuditSink memoryAuditSink;
    private final WebSocketHandler wsHandler;
    private final SessionTokenService tokenService;
    private final Set<String> usedSupervisorSessions = ConcurrentHashMap.newKeySet();
    private Javalin app;

    public LivenessServerApp(ServerConfig config) {
        this.config = config;
        this.memoryAuditSink = new InMemoryAuditSink(10_000);

        AuditSink effectiveSink = this.memoryAuditSink;
        if (config.auditFilePath() != null && !config.auditFilePath().isBlank()) {
            try {
                FileAuditSink fileSink = new FileAuditSink(new java.io.File(config.auditFilePath()));
                effectiveSink = new CompositeAuditSink(memoryAuditSink, fileSink);
            } catch (IOException e) {
                log.error("Failed to initialize FileAuditSink at {}: {}", config.auditFilePath(), e.getMessage());
            }
        }

        this.engine = new DefaultLivenessEngine(
                new ClientLandmarkAnalyzer(),
                new PassiveAnalyzer(),
                new ChallengeGenerator(),
                effectiveSink,
                config.modelPath());
        this.engine.setLockoutDurationMillis(config.lockoutSeconds() * 1000L);
        this.wsHandler = new WebSocketHandler(this.engine, config);
        this.tokenService = new SessionTokenService(config.sessionSecret());
    }

    public Javalin createApp() {
        this.app = Javalin.create(javalinConfig -> {
            javalinConfig.staticFiles.add(staticFiles -> {
                staticFiles.hostedPath = "/";
                staticFiles.directory = "/web";
                staticFiles.location = Location.CLASSPATH;
            });
            javalinConfig.jetty.modifyWebSocketServletFactory(factory -> {
                factory.setMaxTextMessageSize(1024 * 1024);
            });
        });

        // WebSocket endpoint
        app.ws("/ws/liveness", ws -> {
            ws.onConnect(wsHandler::onConnect);
            ws.onMessage(wsHandler::onMessage);
            ws.onClose(wsHandler::onClose);
            ws.onError(wsHandler::onError);
        });

        // REST endpoints
        long serverStartTimeMillis = System.currentTimeMillis();

        // 1. Health endpoint (public)
        app.get("/api/health", ctx -> {
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("status", "UP");
            resp.put("healthy", true);
            resp.put("engineVersion", engine.getEngineVersion());
            resp.put("mode", config.diagnosticMode() ? "diagnostic" : "normal");
            resp.put("demo", config.demoMode());
            resp.put("lockoutSeconds", config.lockoutSeconds());
            resp.put("uptimeSeconds", (System.currentTimeMillis() - serverStartTimeMillis) / 1000);
            resp.put("totalAuditEvents", memoryAuditSink.getAllEvents().size());
            resp.put("auditChainIntegrity", AuditChainVerifier.verifySessions(memoryAuditSink.getAllEvents()).valid());
            resp.put("activeWebSocketSessions", wsHandler.getActiveSessionCount());
            resp.put("timestamp", java.time.Instant.now().toString());
            ctx.json(resp);
        });

        // 2. Authenticated Session Creation endpoint
        app.post("/api/v1/sessions", ctx -> {
            if (!isOriginAllowed(ctx.header("Origin"))) {
                ctx.status(HttpStatus.FORBIDDEN).json(Map.of("error", "Forbidden origin"));
                return;
            }

            try {
                JsonNode body = ctx.body().isBlank() ? null : mapper.readTree(ctx.body());
                String wfStr = (body != null && body.hasNonNull("workflow")) ? body.path("workflow").asText() : "RESIDENT_AUTH";
                WorkflowType workflow = WorkflowType.RESIDENT_AUTH;
                try {
                    workflow = WorkflowType.valueOf(wfStr.trim().toUpperCase());
                } catch (IllegalArgumentException ignored) {
                }

                String clientIdentity = body != null ? body.path("clientIdentity").asText() : "";
                if (clientIdentity.isBlank()) {
                    clientIdentity = ctx.ip();
                }

                String sessionId = java.util.UUID.randomUUID().toString();
                long validityMs = 600_000L; // 10 minutes
                String token = tokenService.issueToken(sessionId, workflow, clientIdentity, validityMs);

                LivenessPolicy policy = resolveWorkflowPolicy(workflow);
                Map<String, Object> resp = new LinkedHashMap<>();
                resp.put("sessionId", sessionId);
                resp.put("token", token);
                resp.put("workflow", workflow.name());
                resp.put("expiresInSeconds", validityMs / 1000);
                resp.put("policy", serializePolicy(workflow, policy));
                ctx.json(resp);
            } catch (Exception e) {
                ctx.status(HttpStatus.BAD_REQUEST).json(Map.of("error", "Invalid request: " + e.getMessage()));
            }
        });

        // 3. Admin-Gated Audit endpoints
        app.get("/api/audit", ctx -> {
            if (!isAuthorizedAdmin(ctx)) {
                ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("error", "Unauthorized: Admin Bearer token required"));
                return;
            }
            List<LivenessAuditEvent> allEvents = memoryAuditSink.getAllEvents();
            ctx.json(allEvents);
        });

        app.get("/api/audit/verify", ctx -> {
            if (!isAuthorizedAdmin(ctx)) {
                ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("error", "Unauthorized: Admin Bearer token required"));
                return;
            }
            List<LivenessAuditEvent> allEvents = memoryAuditSink.getAllEvents();
            AuditChainVerifier.AuditVerificationResult result = AuditChainVerifier.verifySessions(allEvents);
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("valid", result.valid());
            resp.put("count", allEvents.size());
            resp.put("firstBrokenIndex", result.firstBrokenIndex());
            resp.put("message", result.message());
            resp.put("tamperFree", result.valid());
            ctx.json(resp);
        });

        app.get("/api/audit/{sessionId}", ctx -> {
            if (!isAuthorizedAdmin(ctx)) {
                ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("error", "Unauthorized: Admin Bearer token required"));
                return;
            }
            String sessionId = ctx.pathParam("sessionId");
            List<LivenessAuditEvent> events = memoryAuditSink.getEventsForSession(sessionId);
            ctx.json(events);
        });

        app.get("/api/audit/{sessionId}/verify", ctx -> {
            if (!isAuthorizedAdmin(ctx)) {
                ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("error", "Unauthorized: Admin Bearer token required"));
                return;
            }
            String sessionId = ctx.pathParam("sessionId");
            List<LivenessAuditEvent> events = memoryAuditSink.getEventsForSession(sessionId);
            AuditChainVerifier.AuditVerificationResult result = AuditChainVerifier.verify(events);
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("sessionId", sessionId);
            resp.put("valid", result.valid());
            resp.put("count", events.size());
            resp.put("firstBrokenIndex", result.firstBrokenIndex());
            resp.put("message", result.message());
            resp.put("tamperFree", result.valid());
            ctx.json(resp);
        });

        app.post("/api/audit/verify", ctx -> {
            if (!isAuthorizedAdmin(ctx)) {
                ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("error", "Unauthorized: Admin Bearer token required"));
                return;
            }
            try {
                List<LivenessAuditEvent> events = mapper.readValue(
                        ctx.body(),
                        new TypeReference<List<LivenessAuditEvent>>() {
                        });
                AuditChainVerifier.AuditVerificationResult result = AuditChainVerifier.verifySessions(events);
                Map<String, Object> resp = new LinkedHashMap<>();
                resp.put("valid", result.valid());
                resp.put("count", events != null ? events.size() : 0);
                resp.put("firstBrokenIndex", result.firstBrokenIndex());
                resp.put("message", result.message());
                resp.put("tamperFree", result.valid());
                ctx.json(resp);
            } catch (Exception e) {
                ctx.status(HttpStatus.BAD_REQUEST).json(Map.of(
                        "valid", false,
                        "firstBrokenIndex", -1,
                        "message", "Malformed audit events payload: " + e.getMessage()));
            }
        });

        // 4. Admin-Gated Policy endpoints
        app.get("/api/policy", ctx -> {
            if (!isAuthorizedAdmin(ctx)) {
                ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("error", "Unauthorized: Admin Bearer token required"));
                return;
            }
            Map<String, Object> allPolicies = new LinkedHashMap<>();
            for (WorkflowType wf : WorkflowType.values()) {
                LivenessPolicy p = resolveWorkflowPolicy(wf);
                allPolicies.put(wf.name(), serializePolicy(wf, p));
            }
            ctx.json(allPolicies);
        });

        app.get("/api/policy/{workflow}", ctx -> {
            if (!isAuthorizedAdmin(ctx)) {
                ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("error", "Unauthorized: Admin Bearer token required"));
                return;
            }
            String wfParam = ctx.pathParam("workflow").trim().toUpperCase().replace("-", "_");
            WorkflowType wf;
            try {
                wf = WorkflowType.valueOf(wfParam);
            } catch (IllegalArgumentException e) {
                ctx.status(HttpStatus.BAD_REQUEST).json(Map.of(
                        "error", "Unknown workflow: " + wfParam,
                        "validWorkflows",
                        List.of("RESIDENT_AUTH", "RESIDENT_ENROLLMENT", "OPERATOR_AUTH", "SUPERVISOR_AUTH")));
                return;
            }

            LivenessPolicy policy = resolveWorkflowPolicy(wf);
            ctx.json(serializePolicy(wf, policy));
        });

        // 5. Admin-Gated Supervisor Override endpoint
        app.post("/api/supervisor/override", ctx -> {
            if (!isAuthorizedAdmin(ctx)) {
                ctx.status(HttpStatus.UNAUTHORIZED).json(Map.of("error", "Unauthorized: Admin Bearer token required"));
                return;
            }

            try {
                JsonNode body = mapper.readTree(ctx.body());
                String targetSessionId = body.path("targetSessionId").asText().trim();
                String supervisorSessionId = body.path("supervisorSessionId").asText().trim();

                if (targetSessionId.isBlank()) {
                    ctx.status(HttpStatus.BAD_REQUEST).json(Map.of("error", "targetSessionId is required"));
                    return;
                }

                if (supervisorSessionId.isBlank()) {
                    ctx.status(HttpStatus.BAD_REQUEST).json(Map.of("error", "supervisorSessionId is required"));
                    return;
                }

                if (targetSessionId.equals(supervisorSessionId)) {
                    ctx.status(HttpStatus.BAD_REQUEST)
                            .json(Map.of("error", "targetSessionId and supervisorSessionId must be distinct"));
                    return;
                }

                if (usedSupervisorSessions.contains(supervisorSessionId)) {
                    ctx.status(HttpStatus.FORBIDDEN)
                            .json(Map.of("error", "Supervisor session already used (single-use policy)"));
                    return;
                }

                List<LivenessAuditEvent> supervisorEvents = memoryAuditSink.getEventsForSession(supervisorSessionId);
                LivenessAuditEvent acceptedEvent = supervisorEvents.stream()
                        .filter(ev -> ev.decision() == DecisionType.ACCEPTED
                                && ev.workflow() == WorkflowType.SUPERVISOR_AUTH)
                        .findFirst()
                        .orElse(null);

                if (acceptedEvent == null) {
                    ctx.status(HttpStatus.FORBIDDEN).json(Map.of(
                            "error", "Supervisor override requires a valid prior ACCEPTED SUPERVISOR_AUTH session."));
                    return;
                }

                // Check recency: must be within last 5 minutes (300,000 ms)
                long now = System.currentTimeMillis();
                if (now - acceptedEvent.timestampMillis() > 300_000L) {
                    ctx.status(HttpStatus.FORBIDDEN).json(Map.of(
                            "error", "Supervisor session expired (> 5 minutes old)."));
                    return;
                }

                // Enforce single-use
                usedSupervisorSessions.add(supervisorSessionId);
                engine.recordSupervisorOverride(targetSessionId, supervisorSessionId);
                log.info("Supervisor override authorized: supervisor={}, target={}", supervisorSessionId,
                        targetSessionId);

                ctx.json(Map.of(
                        "success", true,
                        "targetSessionId", targetSessionId,
                        "supervisorSessionId", supervisorSessionId,
                        "message", "Supervisor override successfully recorded in audit log."));
            } catch (Exception e) {
                ctx.status(HttpStatus.BAD_REQUEST).json(Map.of("error", "Invalid request body: " + e.getMessage()));
            }
        });

        // Convenience aliases & redirects
        app.get("/health", ctx -> ctx.redirect("/api/health"));
        app.get("/collect", ctx -> ctx.redirect("/collect.html"));

        // 6. Custom 404 Not Found Handler
        app.error(HttpStatus.NOT_FOUND, ctx -> {
            String path = ctx.path();
            if (path.startsWith("/api/")) {
                ctx.contentType("application/json");
                ctx.json(Map.of("error", "Not Found", "status", 404, "path", path));
                return;
            }

            String accept = ctx.header("Accept");
            boolean acceptsHtml = accept != null && accept.contains("text/html");
            boolean isAssetRequest = path.contains(".") && !path.endsWith(".html");

            if (acceptsHtml && !isAssetRequest) {
                ctx.contentType("text/html; charset=UTF-8");
                try (var stream = LivenessServerApp.class.getResourceAsStream("/web/404.html")) {
                    if (stream != null) {
                        ctx.result(stream.readAllBytes());
                    } else {
                        ctx.result(
                                "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>");
                    }
                } catch (Exception ignored) {
                    ctx.result(
                            "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>");
                }
            } else {
                ctx.status(HttpStatus.NOT_FOUND);
                if (accept != null && accept.contains("application/json")) {
                    ctx.contentType("application/json");
                    ctx.json(Map.of("error", "Not Found", "status", 404, "path", path));
                } else {
                    ctx.contentType("text/plain; charset=UTF-8");
                    ctx.result("404 Not Found: " + path);
                }
            }
        });

        return app;
    }

    private boolean isAuthorizedAdmin(io.javalin.http.Context ctx) {
        String authHeader = ctx.header("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return false;
        }
        String token = authHeader.substring(7).trim();
        String expected = config.adminToken();
        if (expected == null || expected.isBlank()) {
            return false;
        }
        return MessageDigest.isEqual(
                token.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8));
    }

    private boolean isOriginAllowed(String origin) {
        if (origin == null || origin.isBlank()) return true;
        List<String> allowed = config.allowedOrigins();
        if (allowed == null || allowed.isEmpty() || allowed.contains("*")) return true;
        for (String a : allowed) {
            if (origin.equalsIgnoreCase(a) || a.equals("*")) return true ;

        }
        return false;
    }

    private static LivenessPolicy resolveWorkflowPolicy(WorkflowType wf) {
        return switch (wf) {
            case RESIDENT_ENROLLMENT -> LivenessPolicy.residentEnrollment();
            case RESIDENT_AUTH -> LivenessPolicy.residentAuth();
            case OPERATOR_AUTH -> LivenessPolicy.operatorAuth();
            case SUPERVISOR_AUTH -> LivenessPolicy.supervisorAuth();
        };
    }

    private static Map<String, Object> serializePolicy(WorkflowType wf, LivenessPolicy policy) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("workflow", wf.name());
        resp.put("description", switch (wf) {
            case RESIDENT_AUTH -> "Rapid passive-first citizen authentication for kiosks and mobile apps";
            case RESIDENT_ENROLLMENT -> "High-assurance passive + active biometric enrollment verification";
            case OPERATOR_AUTH -> "Operator workstation credential validation with rapid active challenges";
            case SUPERVISOR_AUTH -> "High-privilege supervisor authorization with strict attack threshold";
        });
        resp.put("passiveThreshold", policy.passiveThreshold());
        resp.put("padThreshold", policy.padThreshold());
        resp.put("activeEnabled", policy.activeEnabled());
        resp.put("minChallenges", policy.minChallenges());
        resp.put("maxRetries", policy.maxRetries());
        resp.put("passiveWindowFrames", policy.passiveWindowFrames());
        resp.put("activeTimeoutSeconds", policy.activeTimeoutSeconds());
        resp.put("failureBehaviour", policy.failureBehaviour().name());
        resp.put("allowedChallenges", policy.allowedChallengeTypes().stream().map(Enum::name).toList());
        return resp;
    }

    public void start() {
        if (app == null) {
            createApp();
        }
        app.start(config.port());
        log.info("MOSIP Liveness Server started on port {} (mode={}, demo={})",
                config.port(), config.diagnosticMode() ? "diagnostic" : "normal", config.demoMode());
    }

    public void stop() {
        if (app != null) {
            app.stop();
        }
        engine.close();
    }

    public DefaultLivenessEngine getEngine() {
        return engine;
    }

    public InMemoryAuditSink getMemoryAuditSink() {
        return memoryAuditSink;
    }

    public SessionTokenService getTokenService() {
        return tokenService;
    }

    private static class CompositeAuditSink implements AuditSink {
        private final InMemoryAuditSink memory;
        private final FileAuditSink file;

        CompositeAuditSink(InMemoryAuditSink memory, FileAuditSink file) {
            this.memory = memory;
            this.file = file;
        }

        @Override
        public synchronized void append(LivenessAuditEvent event) {
            memory.append(event);
            if (file != null) {
                file.append(event);
            }
        }

        @Override
        public List<LivenessAuditEvent> getEventsForSession(String sessionId) {
            return memory.getEventsForSession(sessionId);
        }

        @Override
        public void close() {
            memory.close();
            if (file != null) {
                file.close();
            }
        }
    }
}
