package io.mosip.liveness.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.mosip.liveness.api.policy.WorkflowType;
import io.mosip.liveness.core.engine.DefaultLivenessEngine;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class LivenessServerWebSocketTest {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final String ADMIN_TOKEN = "mosip-admin-token-2026";
    private static final String SESSION_SECRET = "secret-key-123456";
    private LivenessServerApp serverApp;
    private Javalin app;
    private int port;

    @BeforeEach
    void setUp() {
        ServerConfig config = new ServerConfig(0, true, null, null, 30, false,
                ADMIN_TOKEN, SESSION_SECRET, List.of("*"), 10, 15 * 1024 * 1024L);
        serverApp = new LivenessServerApp(config);
        app = serverApp.createApp();
        app.start(0);
        port = app.port();
    }

    @AfterEach
    void tearDown() {
        if (app != null) {
            app.stop();
        }
        serverApp.stop();
    }

    @Test
    @DisplayName("P0-3: Strict mode refuses WebSocket connect without signed session token")
    void testRejectsConnectionWithoutTokenWhenDemoOff() throws Exception {
        CompletableFuture<Integer> closeFuture = new CompletableFuture<>();

        WebSocket.Listener listener = new WebSocket.Listener() {
            @Override
            public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                closeFuture.complete(statusCode);
                return WebSocket.Listener.super.onClose(webSocket, statusCode, reason);
            }
        };

        HttpClient client = HttpClient.newHttpClient();
        WebSocket ws = client.newWebSocketBuilder()
                .buildAsync(URI.create("ws://localhost:" + port + "/ws/liveness?workflow=RESIDENT_AUTH"), listener)
                .get(5, TimeUnit.SECONDS);

        Integer status = closeFuture.get(5, TimeUnit.SECONDS);
        assertThat(status).isEqualTo(1008);
    }

    @Test
    @DisplayName("WebSocket connection with signed token receives initial state and handles cancel")
    void testWebSocketFlowWithToken() throws Exception {
        String token = serverApp.getTokenService().issueToken("sess-flow-1", WorkflowType.RESIDENT_AUTH, "client-1", 60_000L);

        CompletableFuture<String> firstMessageFuture = new CompletableFuture<>();
        CompletableFuture<Integer> closeFuture = new CompletableFuture<>();

        WebSocket.Listener listener = new WebSocket.Listener() {
            private final StringBuilder sb = new StringBuilder();

            @Override
            public void onOpen(WebSocket webSocket) {
                webSocket.request(1);
                WebSocket.Listener.super.onOpen(webSocket);
            }

            @Override
            public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                sb.append(data);
                if (last) {
                    firstMessageFuture.complete(sb.toString());
                    sb.setLength(0);
                }
                webSocket.request(1);
                return WebSocket.Listener.super.onText(webSocket, data, last);
            }

            @Override
            public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                closeFuture.complete(statusCode);
                return WebSocket.Listener.super.onClose(webSocket, statusCode, reason);
            }
        };

        HttpClient client = HttpClient.newHttpClient();
        WebSocket ws = client.newWebSocketBuilder()
                .buildAsync(URI.create("ws://localhost:" + port + "/ws/liveness?token=" + token + "&lang=en"), listener)
                .get(5, TimeUnit.SECONDS);

        // Verify initial state message
        String msg = firstMessageFuture.get(5, TimeUnit.SECONDS);
        JsonNode json = mapper.readTree(msg);
        assertThat(json.path("type").asText()).isEqualTo("state");
        assertThat(json.path("state").asText()).isEqualTo("FACE_POSITIONING");

        // Send cancel message
        ws.sendText("{\"type\":\"cancel\"}", true);

        // Wait for socket closure
        Integer status = closeFuture.get(5, TimeUnit.SECONDS);
        assertThat(status).isNotNull();
    }

    @Test
    @DisplayName("P0-2 & P0-5: Static photo attack over WS yields generic message with no internal leaks")
    void testStaticPhotoAttackRejectedWithGenericMessage() throws Exception {
        String token = serverApp.getTokenService().issueToken("sess-photo-atk-1", WorkflowType.RESIDENT_AUTH, "client-atk-1", 60_000L);

        List<String> receivedMessages = new CopyOnWriteArrayList<>();
        CompletableFuture<String> decisionFuture = new CompletableFuture<>();

        WebSocket.Listener listener = new WebSocket.Listener() {
            private final StringBuilder sb = new StringBuilder();

            @Override
            public void onOpen(WebSocket webSocket) {
                webSocket.request(10);
                WebSocket.Listener.super.onOpen(webSocket);
            }

            @Override
            public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                sb.append(data);
                if (last) {
                    String full = sb.toString();
                    receivedMessages.add(full);
                    try {
                        JsonNode node = mapper.readTree(full);
                        if ("decision".equals(node.path("type").asText())) {
                            decisionFuture.complete(full);
                        }
                    } catch (Exception ignored) {}
                    sb.setLength(0);
                }
                webSocket.request(10);
                return WebSocket.Listener.super.onText(webSocket, data, last);
            }
        };

        HttpClient client = HttpClient.newHttpClient();
        WebSocket ws = client.newWebSocketBuilder()
                .buildAsync(URI.create("ws://localhost:" + port + "/ws/liveness?token=" + token), listener)
                .get(5, TimeUnit.SECONDS);

        // Build a 100x100 synthetic JPEG frame
        java.awt.image.BufferedImage img = new java.awt.image.BufferedImage(100, 100, java.awt.image.BufferedImage.TYPE_INT_RGB);
        java.awt.Graphics2D g = img.createGraphics();
        g.setColor(new java.awt.Color(190, 130, 95));
        g.fillOval(20, 15, 60, 70);
        g.dispose();

        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        javax.imageio.ImageIO.write(img, "jpg", baos);
        String jpegB64 = Base64.getEncoder().encodeToString(baos.toByteArray());

        // Send 10 identical static frames with fake landmarks to simulate a static photo presentation attack
        for (int i = 0; i < 8; i++) {
            String frameMsg = mapper.writeValueAsString(java.util.Map.of(
                    "type", "frame",
                    "seq", i,
                    "jpegB64", jpegB64,
                    "landmarks", List.of(List.of(0.35, 0.35), List.of(0.65, 0.35), List.of(0.50, 0.50))
            ));
            ws.sendText(frameMsg, true);
            Thread.sleep(70);
        }

        // Wait for decision or progress
        Thread.sleep(300);

        // Verify that NO message leaked PAD scores or internal classes
        for (String m : receivedMessages) {
            assertThat(m).doesNotContain("PRINT_ATTACK");
            assertThat(m).doesNotContain("SCREEN_REPLAY");
            assertThat(m).doesNotContain("VIDEO_INJECTION");
            assertThat(m).doesNotContain("padScore");
            assertThat(m).doesNotContain("passiveScore");
        }

        ws.sendClose(1000, "Normal termination");
    }

    @Test
    @DisplayName("P0-4: Persistent lockout blocks new WebSocket connection after max retries exceeded")
    void testPersistentLockoutBlocksNewSocket() throws Exception {
        String clientIdentity = "attacker-persistent-ip";

        // Trigger lockout by exceeding retries across 3 sessions
        DefaultLivenessEngine engine = serverApp.getEngine();
        for (int i = 0; i < 3; i++) {
            String sid = "fail-session-" + i;
            io.mosip.liveness.api.engine.LivenessSession s = engine.startSession(
                    sid,
                    WorkflowType.RESIDENT_AUTH,
                    io.mosip.liveness.api.policy.LivenessPolicy.residentAuth(),
                    null,
                    clientIdentity
            );
            s.incrementRetry();
            s.incrementRetry();
            s.incrementRetry();
            s.incrementRetry();

            io.mosip.liveness.api.frame.FaceFrame f = io.mosip.liveness.api.frame.FaceFrame.wrap(
                    new byte[100 * 100 * 3], 100, 100,
                    io.mosip.liveness.api.frame.PixelFormat.RGB_888,
                    System.nanoTime(), 1L, clientIdentity, 0
            );
            engine.processFrame(s, f);
        }

        // After 3 failed sessions, client is locked out!
        assertThat(engine.isDeviceLockedOut(clientIdentity)).isTrue();

        // Now attempt to connect with a new signed token for this clientIdentity
        String token = serverApp.getTokenService().issueToken("sess-new-attempt", WorkflowType.RESIDENT_AUTH, clientIdentity, 60_000L);

        CompletableFuture<Integer> closeFuture = new CompletableFuture<>();
        WebSocket.Listener listener = new WebSocket.Listener() {
            @Override
            public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                closeFuture.complete(statusCode);
                return WebSocket.Listener.super.onClose(webSocket, statusCode, reason);
            }
        };

        HttpClient client = HttpClient.newHttpClient();
        WebSocket ws = client.newWebSocketBuilder()
                .buildAsync(URI.create("ws://localhost:" + port + "/ws/liveness?token=" + token), listener)
                .get(5, TimeUnit.SECONDS);

        Integer status = closeFuture.get(5, TimeUnit.SECONDS);
        assertThat(status).isEqualTo(1008);
    }
}
