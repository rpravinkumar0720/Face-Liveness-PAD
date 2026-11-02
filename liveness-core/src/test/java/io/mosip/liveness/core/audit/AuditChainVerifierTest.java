package io.mosip.liveness.core.audit;

import io.mosip.liveness.api.audit.AuditEventType;
import io.mosip.liveness.api.audit.LivenessAuditEvent;
import io.mosip.liveness.api.decision.DecisionType;
import io.mosip.liveness.api.policy.WorkflowType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuditChainVerifierTest {

    private static List<LivenessAuditEvent> createValidSessionChain(String sessionId, int count) {
        List<LivenessAuditEvent> list = new ArrayList<>();
        String prevHash = "0000000000000000000000000000000000000000000000000000000000000000";

        for (int i = 0; i < count; i++) {
            AuditEventType type = (i == 0) ? AuditEventType.SESSION_START :
                    (i == count - 1) ? AuditEventType.FINAL_DECISION : AuditEventType.QUALITY_CHECK;

            DecisionType dec = (i == count - 1) ? DecisionType.ACCEPTED : null;

            LivenessAuditEvent event = LivenessAuditEvent.builder()
                    .sessionId(sessionId)
                    .previousHash(prevHash)
                    .eventType(type)
                    .workflow(WorkflowType.RESIDENT_ENROLLMENT)
                    .decision(dec)
                    .passiveScore(0.92)
                    .deviceId("CAM_01")
                    .details(Map.of("frameIndex", String.valueOf(i)))
                    .build();

            list.add(event);
            prevHash = event.currentHash();
        }
        return list;
    }

    @Test
    @DisplayName("Valid audit chain passes verification")
    void testValidChainPasses() {
        List<LivenessAuditEvent> chain = createValidSessionChain("sess-001", 5);
        AuditChainVerifier.AuditVerificationResult result = AuditChainVerifier.verify(chain);

        assertThat(result.valid()).isTrue();
        assertThat(result.firstBrokenIndex()).isEqualTo(-1);
    }

    @Test
    @DisplayName("Tampering with a single field fails verification at exact index")
    void testFieldTamperDetected() {
        List<LivenessAuditEvent> chain = createValidSessionChain("sess-002", 4);

        // Tamper with index 2 (modify passive score without updating hash)
        LivenessAuditEvent original = chain.get(2);
        LivenessAuditEvent tampered = new LivenessAuditEvent(
                original.eventId(),
                original.sessionId(),
                original.timestampMillis(),
                original.workflow(),
                original.eventType(),
                original.decision(),
                0.1234, // tampered score!
                original.padClassification(),
                original.padScore(),
                original.challengeType(),
                original.errorCode(),
                original.modelVersion(),
                original.deviceId(),
                original.details(),
                original.previousHash(),
                original.currentHash() // unchanged hash!
        );
        chain.set(2, tampered);

        AuditChainVerifier.AuditVerificationResult result = AuditChainVerifier.verify(chain);
        assertThat(result.valid()).isFalse();
        assertThat(result.firstBrokenIndex()).isEqualTo(2);
        assertThat(result.message()).contains("Payload tamper detected");
    }

    @Test
    @DisplayName("Reordering events breaks chain linkage")
    void testReorderingBreaksLinkage() {
        List<LivenessAuditEvent> chain = createValidSessionChain("sess-003", 4);

        // Swap event 1 and event 2
        LivenessAuditEvent e1 = chain.get(1);
        LivenessAuditEvent e2 = chain.get(2);
        chain.set(1, e2);
        chain.set(2, e1);

        AuditChainVerifier.AuditVerificationResult result = AuditChainVerifier.verify(chain);
        assertThat(result.valid()).isFalse();
        assertThat(result.firstBrokenIndex()).isEqualTo(1);
        assertThat(result.message()).contains("linkage broken");
    }

    @Test
    @DisplayName("No biometric image data or embeddings exist in audit events")
    void testNoBiometricDataInAuditDetails() {
        List<LivenessAuditEvent> chain = createValidSessionChain("sess-004", 3);

        for (LivenessAuditEvent event : chain) {
            assertThat(event.details().keySet()).noneMatch(k ->
                    k.toLowerCase().contains("image") ||
                    k.toLowerCase().contains("crop") ||
                    k.toLowerCase().contains("face") ||
                    k.toLowerCase().contains("embedding") ||
                    k.toLowerCase().contains("landmark")
            );
            for (String val : event.details().values()) {
                // Ensure no base64-like long strings or raw bytes
                assertThat(val.length()).isLessThan(200);
            }
        }
    }

    @Test
    @DisplayName("Front truncation (dropping first event) is detected")
    void testFrontTruncationDetected() {
        List<LivenessAuditEvent> chain = createValidSessionChain("sess-005", 4);

        // Drop the first event (so new first event has non-genesis previousHash)
        List<LivenessAuditEvent> truncated = new ArrayList<>(chain.subList(1, chain.size()));

        AuditChainVerifier.AuditVerificationResult result = AuditChainVerifier.verify(truncated);
        assertThat(result.valid()).isFalse();
        assertThat(result.firstBrokenIndex()).isEqualTo(0);
        assertThat(result.message()).contains("Front-truncation detected");
    }

    @Test
    @DisplayName("Tampering with details map breaks hash verification")
    void testDetailsTamperDetected() {
        List<LivenessAuditEvent> chain = createValidSessionChain("sess-006", 3);

        LivenessAuditEvent original = chain.get(1);
        LivenessAuditEvent tampered = new LivenessAuditEvent(
                original.eventId(),
                original.sessionId(),
                original.timestampMillis(),
                original.workflow(),
                original.eventType(),
                original.decision(),
                original.passiveScore(),
                original.padClassification(),
                original.padScore(),
                original.challengeType(),
                original.errorCode(),
                original.modelVersion(),
                original.deviceId(),
                Map.of("frameIndex", "9999"), // Tampered details!
                original.previousHash(),
                original.currentHash()
        );
        chain.set(1, tampered);

        AuditChainVerifier.AuditVerificationResult result = AuditChainVerifier.verify(chain);
        assertThat(result.valid()).isFalse();
        assertThat(result.firstBrokenIndex()).isEqualTo(1);
        assertThat(result.message()).contains("Payload tamper detected");
    }

    @Test
    @DisplayName("Sequential sessions starting at GENESIS all verify as valid")
    void testSequentialSessionsVerify() {
        List<LivenessAuditEvent> s1 = createValidSessionChain("sess-A", 3);
        List<LivenessAuditEvent> s2 = createValidSessionChain("sess-B", 3);

        List<LivenessAuditEvent> combined = new ArrayList<>();
        combined.addAll(s1);
        combined.addAll(s2);

        AuditChainVerifier.AuditVerificationResult result = AuditChainVerifier.verify(combined);
        assertThat(result.valid()).isTrue();
        assertThat(result.message()).contains("verified (6 events)");
    }

    @Test
    @DisplayName("HMAC signature on final event verifies and detects unkeyed recomputation")
    void testHmacSignatureVerification() {
        String hmacKey = "test-audit-secret-key-xyz";
        List<LivenessAuditEvent> chain = createValidSessionChain("sess-signed", 3);

        // Sign final event
        int lastIdx = chain.size() - 1;
        LivenessAuditEvent last = chain.get(lastIdx);
        String sig = LivenessAuditEvent.computeHmacSignature(hmacKey, last.currentHash());
        LivenessAuditEvent signedLast = new LivenessAuditEvent(
                last.eventId(), last.sessionId(), last.timestampMillis(), last.workflow(),
                last.eventType(), last.decision(), last.passiveScore(), last.padClassification(),
                last.padScore(), last.challengeType(), last.errorCode(), last.modelVersion(),
                last.deviceId(), last.details(), last.previousHash(), last.currentHash(), sig
        );
        chain.set(lastIdx, signedLast);

        // Valid signature verifies
        AuditChainVerifier.AuditVerificationResult resValid = AuditChainVerifier.verify(chain, hmacKey);
        assertThat(resValid.valid()).isTrue();

        // Verification with wrong key fails
        AuditChainVerifier.AuditVerificationResult resWrongKey = AuditChainVerifier.verify(chain, "wrong-key");
        assertThat(resWrongKey.valid()).isFalse();
        assertThat(resWrongKey.message()).contains("Final event signature invalid");

        // Recomputed chain without key (missing signature) fails
        LivenessAuditEvent unsignedLast = new LivenessAuditEvent(
                last.eventId(), last.sessionId(), last.timestampMillis(), last.workflow(),
                last.eventType(), last.decision(), last.passiveScore(), last.padClassification(),
                last.padScore(), last.challengeType(), last.errorCode(), last.modelVersion(),
                last.deviceId(), last.details(), last.previousHash(), last.currentHash(), null
        );
        chain.set(lastIdx, unsignedLast);
        AuditChainVerifier.AuditVerificationResult resNoSig = AuditChainVerifier.verify(chain, hmacKey);
        assertThat(resNoSig.valid()).isFalse();
        assertThat(resNoSig.message()).contains("signature missing");
    }

    @Test
    @DisplayName("P2-2: Property test - modifying ANY field in ANY event k in a chain of length N always breaks verification at k")
    void testAuditChainPropertyTesting() {
        java.util.Random rnd = new java.util.Random(42L);

        for (int chainLen = 2; chainLen <= 12; chainLen++) {
            List<LivenessAuditEvent> originalChain = createValidSessionChain("prop-sess-" + chainLen, chainLen);

            // Property 1: Baseline valid chain always passes
            AuditChainVerifier.AuditVerificationResult baseRes = AuditChainVerifier.verify(originalChain);
            assertThat(baseRes.valid()).isTrue();

            // Property 2: Modifying any field in event k always breaks verification at k
            for (int k = 0; k < chainLen; k++) {
                List<LivenessAuditEvent> tamperedChain = new ArrayList<>(originalChain);
                LivenessAuditEvent target = tamperedChain.get(k);

                // Modify one random attribute among: timestamp, passiveScore, padScore, details
                int fieldChoice = rnd.nextInt(4);
                LivenessAuditEvent modified = switch (fieldChoice) {
                    case 0 -> new LivenessAuditEvent(target.eventId(), target.sessionId(), target.timestampMillis() + 9999L,
                            target.workflow(), target.eventType(), target.decision(), target.passiveScore(),
                            target.padClassification(), target.padScore(), target.challengeType(), target.errorCode(),
                            target.modelVersion(), target.deviceId(), target.details(), target.previousHash(), target.currentHash());
                    case 1 -> new LivenessAuditEvent(target.eventId(), target.sessionId(), target.timestampMillis(),
                            target.workflow(), target.eventType(), target.decision(), target.passiveScore() + 0.05,
                            target.padClassification(), target.padScore(), target.challengeType(), target.errorCode(),
                            target.modelVersion(), target.deviceId(), target.details(), target.previousHash(), target.currentHash());
                    case 2 -> new LivenessAuditEvent(target.eventId(), target.sessionId(), target.timestampMillis(),
                            target.workflow(), target.eventType(), target.decision(), target.passiveScore(),
                            target.padClassification(), 0.999, target.challengeType(), target.errorCode(),
                            target.modelVersion(), target.deviceId(), target.details(), target.previousHash(), target.currentHash());
                    default -> new LivenessAuditEvent(target.eventId(), target.sessionId(), target.timestampMillis(),
                            target.workflow(), target.eventType(), target.decision(), target.passiveScore(),
                            target.padClassification(), target.padScore(), target.challengeType(), target.errorCode(),
                            target.modelVersion(), target.deviceId(), Map.of("tamperedKey", "tamperedVal"),
                            target.previousHash(), target.currentHash());
                };

                tamperedChain.set(k, modified);
                AuditChainVerifier.AuditVerificationResult result = AuditChainVerifier.verify(tamperedChain);

                assertThat(result.valid())
                        .as("Tampered chain must be invalid (length=%d, tamperedIndex=%d, field=%d)", chainLen, k, fieldChoice)
                        .isFalse();
                assertThat(result.firstBrokenIndex())
                        .as("First broken index must match tampered index k")
                        .isEqualTo(k);
            }
        }
    }
}

