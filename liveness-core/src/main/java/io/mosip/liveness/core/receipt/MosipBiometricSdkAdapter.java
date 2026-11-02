package io.mosip.liveness.core.receipt;

import io.mosip.liveness.api.decision.DecisionType;
import io.mosip.liveness.api.decision.LivenessDecision;
import io.mosip.liveness.api.policy.LivenessPolicy;
import io.mosip.liveness.api.policy.WorkflowType;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * Adapter demonstrating consumption of MOSIP Liveness Receipts and compliance verification
 * by MOSIP Registration Client, MOSIP Auth Service (IDA), or MOSIP Device Service (MDS 1.2.0).
 */
public class MosipBiometricSdkAdapter {

    private final byte[] secretKey;

    public MosipBiometricSdkAdapter(byte[] secretKey) {
        this.secretKey = Objects.requireNonNull(secretKey, "secretKey must not be null");
    }

    /**
     * Issues an official MOSIP liveness assertion token for an accepted decision.
     */
    public MosipLivenessReceipt createLivenessAssertion(
            LivenessDecision decision,
            LivenessPolicy policy,
            String challengeNonce,
            long validitySeconds) {

        if (decision.decisionType() != DecisionType.ACCEPTED) {
            throw new IllegalStateException("Cannot issue receipt for non-accepted decision: " + decision.decisionType());
        }

        String policyHash = computePolicyHash(policy);
        return MosipLivenessReceipt.issue(decision, challengeNonce, policyHash, secretKey, validitySeconds);
    }

    /**
     * Validates a presented liveness assertion receipt on behalf of MOSIP Registration Client or IDA.
     *
     * @param jwsToken received JWS compact receipt
     * @param expectedNonce expected challenge nonce from registration context
     * @param expectedWorkflow expected workflow type (e.g. RESIDENT_ENROLLMENT)
     * @return true if receipt is authentic, unexpired, matching nonce, and ACCEPTED
     */
    public boolean verifyLivenessAssertion(String jwsToken, String expectedNonce, WorkflowType expectedWorkflow) {
        try {
            MosipLivenessReceipt receipt = MosipLivenessReceipt.verify(jwsToken, secretKey, expectedNonce);
            if (!"ACCEPTED".equalsIgnoreCase(receipt.decision())) {
                return false;
            }
            if (expectedWorkflow != null && !expectedWorkflow.name().equalsIgnoreCase(receipt.workflow())) {
                return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Computes a deterministic SHA-256 fingerprint of the policy configuration for audit binding.
     */
    public static String computePolicyHash(LivenessPolicy policy) {
        if (policy == null) return "0000000000000000000000000000000000000000000000000000000000000000";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String repr = String.format(java.util.Locale.ROOT,
                    "passiveThresh=%.4f;padThresh=%.4f;window=%d;active=%b;minChal=%d;maxRetries=%d",
                    policy.passiveThreshold(),
                    policy.padThreshold(),
                    policy.passiveWindowFrames(),
                    policy.activeEnabled(),
                    policy.minChallenges(),
                    policy.maxRetries()
            );
            byte[] hash = md.digest(repr.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "policy-hash-error";
        }
    }
}
