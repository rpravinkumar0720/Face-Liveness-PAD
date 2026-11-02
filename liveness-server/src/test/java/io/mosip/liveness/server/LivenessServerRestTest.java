package io.mosip.liveness.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.mosip.liveness.api.audit.AuditEventType;
import io.mosip.liveness.api.audit.LivenessAuditEvent;
import io.mosip.liveness.api.decision.DecisionType;
import io.mosip.liveness.api.policy.WorkflowType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class LivenessServerRestTest {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final String ADMIN_TOKEN = "mosip-admin-token-2026";
    private LivenessServerApp serverApp;
    private Javalin app;
    private int port;
    private HttpClient client;

    @BeforeEach
    void setUp() {
        ServerConfig config = new ServerConfig(0, true, null, null, 30, false,
                ADMIN_TOKEN, "secret-key-123", List.of("*"), 10, 15 * 1024 * 1024L);
        serverApp = new LivenessServerApp(config);
        app = serverApp.createApp();
        app.start(0);
        port = app.port();
        client = HttpClient.newHttpClient();
    }

    @AfterEach
    void tearDown() {
        if (app != null) {
            app.stop();
        }
        serverApp.stop();
    }

    @Test
    @DisplayName("GET /api/health returns UP, version details and multi-session integrity")
    void healthEndpoint() throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/health"))
                .GET()
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).isEqualTo(200);

        JsonNode json = mapper.readTree(resp.body());
        assertThat(json.path("status").asText()).isEqualTo("UP");
        assertThat(json.path("engineVersion").asText()).contains("mosip-liveness-core");
        assertThat(json.path("mode").asText()).isEqualTo("diagnostic");
        assertThat(json.path("auditChainIntegrity").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("P0-2: Unauthenticated GET /api/audit* and /api/policy* return 401")
    void unauthenticatedAuditAndPolicyReturn401() throws Exception {
        // Audit root
        HttpRequest req1 = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/audit"))
                .GET()
                .build();
        assertThat(client.send(req1, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);

        // Audit by session
        HttpRequest req2 = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/audit/session-xyz"))
                .GET()
                .build();
        assertThat(client.send(req2, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);

        // Policy root
        HttpRequest req3 = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/policy"))
                .GET()
                .build();
        assertThat(client.send(req3, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);

        // Policy by workflow
        HttpRequest req4 = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/policy/RESIDENT_AUTH"))
                .GET()
                .build();
        assertThat(client.send(req4, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);
    }

    @Test
    @DisplayName("P0-3: POST /api/v1/sessions issues a signed session token bound to workflow")
    void sessionIssuanceEndpoint() throws Exception {
        String body = mapper.writeValueAsString(Map.of(
                "workflow", "RESIDENT_ENROLLMENT",
                "clientIdentity", "client-device-42"
        ));

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/sessions"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).isEqualTo(200);

        JsonNode json = mapper.readTree(resp.body());
        assertThat(json.path("sessionId").asText()).isNotBlank();
        String token = json.path("token").asText();
        assertThat(token).isNotBlank();
        assertThat(json.path("workflow").asText()).isEqualTo("RESIDENT_ENROLLMENT");

        // Verify that token service verifies this token
        SessionTokenService.SessionToken verified = serverApp.getTokenService().verifyToken(token);
        assertThat(verified.valid()).isTrue();
        assertThat(verified.workflow()).isEqualTo(WorkflowType.RESIDENT_ENROLLMENT);
        assertThat(verified.clientIdentity()).isEqualTo("client-device-42");
    }

    @Test
    @DisplayName("GET /api/policy/{workflow} with admin token returns effective policy parameters")
    void policyEndpointWithAuth() throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/policy/RESIDENT_AUTH"))
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .GET()
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).isEqualTo(200);

        JsonNode json = mapper.readTree(resp.body());
        assertThat(json.path("workflow").asText()).isEqualTo("RESIDENT_AUTH");
        assertThat(json.path("passiveThreshold").asDouble()).isGreaterThan(0.0);
        assertThat(json.path("maxRetries").asInt()).isEqualTo(3);
    }

    @Test
    @DisplayName("POST /api/audit/verify with admin token validates chain integrity and detects tamper")
    void auditVerifyEndpointWithAuth() throws Exception {
        String session = "test-session-123";
        LivenessAuditEvent ev1 = LivenessAuditEvent.builder()
                .sessionId(session)
                .workflow(WorkflowType.RESIDENT_AUTH)
                .eventType(AuditEventType.SESSION_START)
                .decision(DecisionType.RETRY)
                .previousHash("0000000000000000000000000000000000000000000000000000000000000000")
                .build();

        LivenessAuditEvent ev2 = LivenessAuditEvent.builder()
                .sessionId(session)
                .workflow(WorkflowType.RESIDENT_AUTH)
                .eventType(AuditEventType.FINAL_DECISION)
                .decision(DecisionType.ACCEPTED)
                .previousHash(ev1.currentHash())
                .build();

        List<LivenessAuditEvent> validChain = List.of(ev1, ev2);
        String body = mapper.writeValueAsString(validChain);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/audit/verify"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).isEqualTo(200);

        JsonNode json = mapper.readTree(resp.body());
        assertThat(json.path("valid").asBoolean()).isTrue();
        assertThat(json.path("firstBrokenIndex").asInt()).isEqualTo(-1);

        // Tamper with second event
        LivenessAuditEvent tampered = new LivenessAuditEvent(
                ev2.eventId(),
                ev2.sessionId(),
                ev2.timestampMillis(),
                ev2.workflow(),
                ev2.eventType(),
                DecisionType.REJECTED, // Tampered decision
                ev2.passiveScore(),
                ev2.padClassification(),
                ev2.padScore(),
                ev2.challengeType(),
                ev2.errorCode(),
                ev2.modelVersion(),
                ev2.deviceId(),
                ev2.details(),
                ev2.previousHash(),
                ev2.currentHash(),
                null
        );

        String tamperedBody = mapper.writeValueAsString(List.of(ev1, tampered));
        HttpRequest req2 = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/audit/verify"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(tamperedBody))
                .build();

        HttpResponse<String> resp2 = client.send(req2, HttpResponse.BodyHandlers.ofString());
        assertThat(resp2.statusCode()).isEqualTo(200);
        JsonNode json2 = mapper.readTree(resp2.body());
        assertThat(json2.path("valid").asBoolean()).isFalse();
        assertThat(json2.path("firstBrokenIndex").asInt()).isEqualTo(1);
    }

    @Test
    @DisplayName("P0-3: POST /api/supervisor/override validates every rejection path and succeeds on valid auth")
    void supervisorOverrideRejectionPaths() throws Exception {
        // 1. Missing admin token -> 401
        HttpRequest unauthReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/supervisor/override"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build();
        assertThat(client.send(unauthReq, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);

        // 2. Same target and supervisor session -> 400
        String samePayload = mapper.writeValueAsString(Map.of(
                "targetSessionId", "session-A",
                "supervisorSessionId", "session-A"
        ));
        HttpRequest sameReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/supervisor/override"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(samePayload))
                .build();
        assertThat(client.send(sameReq, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400);

        // 3. Supervisor session has no prior ACCEPTED SUPERVISOR_AUTH -> 403
        String missingSupPayload = mapper.writeValueAsString(Map.of(
                "targetSessionId", "locked-session-100",
                "supervisorSessionId", "sup-unauthorized"
        ));
        HttpRequest missingSupReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/supervisor/override"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(missingSupPayload))
                .build();
        assertThat(client.send(missingSupReq, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);

        // 4. Supervisor session expired (> 5 minutes ago) -> 403
        String expiredSupId = "sup-expired";
        LivenessAuditEvent expiredEvent = LivenessAuditEvent.builder()
                .sessionId(expiredSupId)
                .workflow(WorkflowType.SUPERVISOR_AUTH)
                .eventType(AuditEventType.FINAL_DECISION)
                .decision(DecisionType.ACCEPTED)
                .timestampMillis(System.currentTimeMillis() - 400_000L) // 6.6 min ago
                .previousHash("0000000000000000000000000000000000000000000000000000000000000000")
                .build();
        serverApp.getMemoryAuditSink().append(expiredEvent);

        String expiredPayload = mapper.writeValueAsString(Map.of(
                "targetSessionId", "locked-session-101",
                "supervisorSessionId", expiredSupId
        ));
        HttpRequest expiredReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/supervisor/override"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(expiredPayload))
                .build();
        assertThat(client.send(expiredReq, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);

        // 5. Valid recent supervisor session -> 200 OK
        String validSupId = "sup-valid-999";
        LivenessAuditEvent validSupEvent = LivenessAuditEvent.builder()
                .sessionId(validSupId)
                .workflow(WorkflowType.SUPERVISOR_AUTH)
                .eventType(AuditEventType.FINAL_DECISION)
                .decision(DecisionType.ACCEPTED)
                .timestampMillis(System.currentTimeMillis() - 30_000L) // 30s ago
                .previousHash("0000000000000000000000000000000000000000000000000000000000000000")
                .build();
        serverApp.getMemoryAuditSink().append(validSupEvent);

        String validPayload = mapper.writeValueAsString(Map.of(
                "targetSessionId", "locked-session-102",
                "supervisorSessionId", validSupId
        ));
        HttpRequest validReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/supervisor/override"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + ADMIN_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(validPayload))
                .build();
        HttpResponse<String> validResp = client.send(validReq, HttpResponse.BodyHandlers.ofString());
        assertThat(validResp.statusCode()).isEqualTo(200);

        // 6. Reuse / Replay of the same supervisor session -> 403 (single-use enforced!)
        HttpResponse<String> replayResp = client.send(validReq, HttpResponse.BodyHandlers.ofString());
        assertThat(replayResp.statusCode()).isEqualTo(403);
    }

    @Test
    @DisplayName("Custom 404: Returns branded HTML on browser navigation to unknown path")
    void custom404HtmlHandler() throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/nonexistent-page-url"))
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .GET()
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).isEqualTo(404);
        assertThat(resp.headers().firstValue("Content-Type").orElse("")).contains("text/html");
        assertThat(resp.body()).contains("Page Not Found");
        assertThat(resp.body()).contains("404");
    }

    @Test
    @DisplayName("Custom 404: Returns JSON on unknown /api/* endpoint")
    void custom404ApiJsonHandler() throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/unknown-endpoint"))
                .GET()
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).isEqualTo(404);
        assertThat(resp.headers().firstValue("Content-Type").orElse("")).contains("application/json");

        JsonNode json = mapper.readTree(resp.body());
        assertThat(json.path("error").asText()).isEqualTo("Not Found");
        assertThat(json.path("status").asInt()).isEqualTo(404);
        assertThat(json.path("path").asText()).isEqualTo("/api/v1/unknown-endpoint");
    }

    @Test
    @DisplayName("Custom 404: Missing static asset returns plain 404, not HTML")
    void custom404StaticAssetHandler() throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/vendor/missing-library.js"))
                .header("Accept", "*/*")
                .GET()
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).isEqualTo(404);
        assertThat(resp.headers().firstValue("Content-Type").orElse("")).doesNotContain("text/html");
    }

    @Test
    @DisplayName("Convenience Redirects: /health -> /api/health and /collect -> /collect.html")
    void convenienceRedirects() throws Exception {
        HttpClient noRedirectClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        HttpRequest healthReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/health"))
                .GET()
                .build();
        HttpResponse<Void> healthResp = noRedirectClient.send(healthReq, HttpResponse.BodyHandlers.discarding());
        assertThat(healthResp.statusCode()).isEqualTo(302);
        assertThat(healthResp.headers().firstValue("Location").orElse("")).isEqualTo("/api/health");

        HttpRequest collectReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/collect"))
                .GET()
                .build();
        HttpResponse<Void> collectResp = noRedirectClient.send(collectReq, HttpResponse.BodyHandlers.discarding());
        assertThat(collectResp.statusCode()).isEqualTo(302);
        assertThat(collectResp.headers().firstValue("Location").orElse("")).isEqualTo("/collect.html");
    }
}
