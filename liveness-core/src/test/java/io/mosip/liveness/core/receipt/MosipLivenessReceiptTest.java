package io.mosip.liveness.core.receipt;

import io.mosip.liveness.api.decision.LivenessDecision;
import io.mosip.liveness.api.policy.LivenessPolicy;
import io.mosip.liveness.api.policy.WorkflowType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MosipLivenessReceiptTest {

    private static final byte[] TEST_KEY = "test-secret-key-1234567890123456".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("issue and verify round-trip produces authentic JWS receipt")
    void testIssueAndVerifyRoundTrip() {
        LivenessDecision decision = LivenessDecision.accepted(
                "session-xyz-123",
                WorkflowType.RESIDENT_AUTH,
                null,
                List.of(),
                0.96,
                null
        );

        String nonce = "challenge-nonce-abc";
        String policyHash = "policy-hash-456";

        MosipLivenessReceipt receipt = MosipLivenessReceipt.issue(decision, nonce, policyHash, TEST_KEY, 300);

        assertThat(receipt.sessionId()).isEqualTo("session-xyz-123");
        assertThat(receipt.nonce()).isEqualTo(nonce);
        assertThat(receipt.decision()).isEqualTo("ACCEPTED");
        assertThat(receipt.workflow()).isEqualTo("RESIDENT_AUTH");
        assertThat(receipt.jwsToken()).isNotBlank();
        assertThat(receipt.jwsToken().split("\\.")).hasSize(3);

        // Verification with matching key and nonce
        MosipLivenessReceipt verified = MosipLivenessReceipt.verify(receipt.jwsToken(), TEST_KEY, nonce);
        assertThat(verified.sessionId()).isEqualTo(receipt.sessionId());
        assertThat(verified.nonce()).isEqualTo(receipt.nonce());
        assertThat(verified.decision()).isEqualTo("ACCEPTED");
    }

    @Test
    @DisplayName("tampered JWS token or invalid signature throws SecurityException")
    void testTamperedSignatureFails() {
        LivenessDecision decision = LivenessDecision.accepted(
                "session-1",
                WorkflowType.RESIDENT_AUTH,
                null,
                List.of(),
                0.95,
                null
        );

        MosipLivenessReceipt receipt = MosipLivenessReceipt.issue(decision, "nonce-1", "p-hash", TEST_KEY, 300);

        byte[] wrongKey = "wrong-key-0000000000000000000000000".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> MosipLivenessReceipt.verify(receipt.jwsToken(), wrongKey, "nonce-1"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("signature verification failed");
    }

    @Test
    @DisplayName("nonce mismatch throws SecurityException")
    void testNonceMismatchFails() {
        LivenessDecision decision = LivenessDecision.accepted(
                "session-1",
                WorkflowType.RESIDENT_AUTH,
                null,
                List.of(),
                0.95,
                null
        );

        MosipLivenessReceipt receipt = MosipLivenessReceipt.issue(decision, "correct-nonce", "p-hash", TEST_KEY, 300);

        assertThatThrownBy(() -> MosipLivenessReceipt.verify(receipt.jwsToken(), TEST_KEY, "wrong-nonce"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Challenge nonce mismatch");
    }

    @Test
    @DisplayName("MosipBiometricSdkAdapter creates and validates liveness assertion")
    void testSdkAdapterAssertion() {
        MosipBiometricSdkAdapter adapter = new MosipBiometricSdkAdapter(TEST_KEY);
        LivenessPolicy policy = LivenessPolicy.residentAuth();

        LivenessDecision decision = LivenessDecision.accepted(
                "sess-adapter-1",
                WorkflowType.RESIDENT_AUTH,
                null,
                List.of(),
                0.97,
                null
        );

        MosipLivenessReceipt receipt = adapter.createLivenessAssertion(decision, policy, "nonce-m-1", 120);
        assertThat(receipt.jwsToken()).isNotNull();

        boolean valid = adapter.verifyLivenessAssertion(receipt.jwsToken(), "nonce-m-1", WorkflowType.RESIDENT_AUTH);
        assertThat(valid).isTrue();

        boolean invalidNonce = adapter.verifyLivenessAssertion(receipt.jwsToken(), "bad-nonce", WorkflowType.RESIDENT_AUTH);
        assertThat(invalidNonce).isFalse();

        boolean invalidWorkflow = adapter.verifyLivenessAssertion(receipt.jwsToken(), "nonce-m-1", WorkflowType.OPERATOR_AUTH);
        assertThat(invalidWorkflow).isFalse();
    }
}
