package io.mosip.liveness.eval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.liveness.api.challenge.ChallengeType;
import io.mosip.liveness.api.decision.DecisionType;
import io.mosip.liveness.api.decision.LivenessDecision;
import io.mosip.liveness.api.engine.LivenessSession;
import io.mosip.liveness.api.frame.FaceFrame;
import io.mosip.liveness.api.frame.PixelFormat;
import io.mosip.liveness.api.policy.FailureBehaviour;
import io.mosip.liveness.api.policy.LivenessPolicy;
import io.mosip.liveness.api.policy.WorkflowType;
import io.mosip.liveness.api.quality.Point2D;
import io.mosip.liveness.core.analyzer.ClientLandmarkAnalyzer;
import io.mosip.liveness.core.audit.InMemoryAuditSink;
import io.mosip.liveness.core.challenge.ChallengeGenerator;
import io.mosip.liveness.core.engine.DefaultLivenessEngine;
import io.mosip.liveness.core.passive.PassiveAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.*;

/**
 * Runs presentation attack evaluation benchmarks on labeled directories of frame sequences
 * and computes ISO/IEC 30107-3 metrics (APCER, BPCER, DET curves, Clopper-Pearson CIs, latencies).
 */
public class Evaluator {

    private static final Logger log = LoggerFactory.getLogger(Evaluator.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    public record PresentationResult(
            String presentationId,
            String category,
            int totalFrames,
            DecisionType finalDecision,
            double livenessScore,
            long latencyNanos,
            String details
    ) {}

    public record CategoryMetrics(
            String category,
            int totalPresentations,
            int acceptedCount,
            int rejectedCount,
            int retryOrInconclusiveCount,
            double errorRatePercent, // APCER for attacks, BPCER for genuine
            double ciLowerPercent,
            double ciUpperPercent,
            double latencyP50Ms,
            double latencyP95Ms
    ) {}

    public record DetPoint(
            double threshold,
            double apcerPercent,
            double bpcerPercent
    ) {}

    private final String modelPath;
    private final boolean activeEnabled;
    private final double passiveThreshold;
    private final double padThreshold;

    public Evaluator(String modelPath) {
        this(modelPath, false, 0.80, 0.70);
    }

    public Evaluator(String modelPath, boolean activeEnabled, double passiveThreshold, double padThreshold) {
        this.modelPath = modelPath;
        this.activeEnabled = activeEnabled;
        this.passiveThreshold = passiveThreshold;
        this.padThreshold = padThreshold;
    }

    /**
     * Evaluates a directory containing subdirectories of presentations.
     */
    public List<PresentationResult> evaluateCategory(File categoryDir, String categoryName) {
        if (categoryDir == null || !categoryDir.exists() || !categoryDir.isDirectory()) {
            return Collections.emptyList();
        }

        File[] subDirs = categoryDir.listFiles(File::isDirectory);
        List<PresentationResult> results = new ArrayList<>();

        if (subDirs != null && subDirs.length > 0) {
            Arrays.sort(subDirs, Comparator.comparing(File::getName));
            for (File presentationDir : subDirs) {
                results.add(evaluateSinglePresentation(presentationDir, categoryName));
            }
        } else {
            File[] images = categoryDir.listFiles(f -> isImageFile(f.getName()));
            if (images != null && images.length > 0) {
                results.add(evaluateSinglePresentation(categoryDir, categoryName));
            }
        }

        return results;
    }

    public PresentationResult evaluateSinglePresentation(File presentationDir, String categoryName) {
        File[] imageFiles = presentationDir.listFiles(f -> isImageFile(f.getName()));
        if (imageFiles == null || imageFiles.length == 0) {
            return new PresentationResult(presentationDir.getName(), categoryName, 0, DecisionType.ERROR, 0.0, 0L, "No image files found");
        }

        Arrays.sort(imageFiles, Comparator.comparing(File::getName));

        ClientLandmarkAnalyzer clientAnalyzer = new ClientLandmarkAnalyzer();
        DefaultLivenessEngine engine = new DefaultLivenessEngine(
                clientAnalyzer,
                new PassiveAnalyzer(),
                new ChallengeGenerator(),
                new InMemoryAuditSink(500),
                modelPath
        );

        File timelineJson = new File(presentationDir, "timeline.json");
        String challengeType = "NONE";
        if (timelineJson.exists()) {
            try {
                JsonNode tlNode = mapper.readTree(timelineJson);
                challengeType = tlNode.hasNonNull("challengeType") ? tlNode.path("challengeType").asText() : "NONE";
            } catch (Exception ignored) {}
        }
        boolean runActive = activeEnabled || (!"NONE".equalsIgnoreCase(challengeType) && !challengeType.isEmpty());

        LivenessPolicy policy = LivenessPolicy.builder()
                .passiveThreshold(passiveThreshold)
                .padThreshold(padThreshold)
                .activeEnabled(runActive)
                .minChallenges(runActive ? 1 : 0)
                .allowedChallengeTypes(runActive ? Set.of(ChallengeType.BLINK, ChallengeType.SMILE, ChallengeType.TURN_LEFT, ChallengeType.TURN_RIGHT) : Set.of())
                .passiveWindowFrames(Math.min(5, Math.max(1, imageFiles.length)))
                .failureBehaviour(FailureBehaviour.BLOCK)
                .build();

        String sessionId = "eval-" + UUID.randomUUID();
        LivenessSession session = engine.startSession(sessionId, WorkflowType.RESIDENT_AUTH, policy, null);

        DecisionType lastDecision = DecisionType.RETRY;
        double lastScore = 0.0;
        int frameSeq = 0;
        long startNanos = System.nanoTime();

        try {
            for (File imgFile : imageFiles) {
                BufferedImage bImg = ImageIO.read(imgFile);
                if (bImg == null) continue;

                int w = bImg.getWidth();
                int h = bImg.getHeight();
                byte[] rgb = new byte[w * h * 3];
                int[] pixels = bImg.getRGB(0, 0, w, h, null, 0, w);
                for (int i = 0; i < pixels.length; i++) {
                    int p = pixels[i];
                    rgb[i * 3] = (byte) ((p >> 16) & 0xFF);
                    rgb[i * 3 + 1] = (byte) ((p >> 8) & 0xFF);
                    rgb[i * 3 + 2] = (byte) (p & 0xFF);
                }

                File sidecarJson = getSidecarFile(imgFile);
                if (sidecarJson != null && sidecarJson.exists()) {
                    List<Point2D> points = parseSidecarPoints(sidecarJson);
                    if (!points.isEmpty()) {
                        clientAnalyzer.pushLandmarks(sessionId, points, 0.99, 1);
                    }
                }

                FaceFrame frame = FaceFrame.wrap(rgb, w, h, PixelFormat.RGB_888, System.nanoTime(), frameSeq++, sessionId, 0);
                try {
                    LivenessDecision decision = engine.processFrame(session, frame);
                    lastDecision = decision.decisionType();
                    lastScore = decision.finalScore();


                    if (lastDecision == DecisionType.ACCEPTED || lastDecision == DecisionType.REJECTED) {
                        break;
                    }
                } finally {
                    if (!frame.isWiped()) {
                        frame.wipe();
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error evaluating presentation {}: {}", presentationDir.getName(), e.getMessage());
            lastDecision = DecisionType.ERROR;
        } finally {
            engine.close();
        }

        long elapsedNanos = System.nanoTime() - startNanos;

        return new PresentationResult(
                presentationDir.getName(),
                categoryName,
                imageFiles.length,
                lastDecision,
                lastScore,
                elapsedNanos,
                "Frames: " + imageFiles.length
        );
    }

    public static CategoryMetrics computeMetrics(String category, List<PresentationResult> results, boolean isAttack) {
        int total = results.size();
        if (total == 0) {
            return new CategoryMetrics(category, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0);
        }

        int accepted = 0;
        int rejected = 0;
        int retryOrError = 0;
        List<Double> latenciesMs = new ArrayList<>(total);

        for (PresentationResult r : results) {
            latenciesMs.add(r.latencyNanos() / 1_000_000.0);
            if (r.finalDecision() == DecisionType.ACCEPTED) {
                accepted++;
            } else if (r.finalDecision() == DecisionType.REJECTED || r.finalDecision() == DecisionType.FAILED_MAX_RETRIES) {
                rejected++;
            } else {
                retryOrError++;
            }
        }

        Collections.sort(latenciesMs);
        double p50 = latenciesMs.get((int) (latenciesMs.size() * 0.50));
        double p95 = latenciesMs.get(Math.min(latenciesMs.size() - 1, (int) (latenciesMs.size() * 0.95)));

        int errors = isAttack ? accepted : (rejected + retryOrError);
        double errorRate = ((double) errors / total) * 100.0;
        double[] ci = computeClopperPearsonCI(errors, total, 0.95);

        return new CategoryMetrics(category, total, accepted, rejected, retryOrError, errorRate, ci[0], ci[1], p50, p95);
    }

    /**
     * Computes exact Clopper-Pearson 95% Confidence Interval for a binomial proportion.
     */
    public static double[] computeClopperPearsonCI(int k, int n, double confidenceLevel) {
        if (n <= 0) return new double[]{ 0.0, 0.0 };
        double alpha = 1.0 - confidenceLevel;
        if (k <= 0) {
            double upper = 1.0 - Math.pow(alpha / 2.0, 1.0 / n);
            return new double[]{ 0.0, upper * 100.0 };
        }
        if (k >= n) {
            double lower = Math.pow(alpha / 2.0, 1.0 / n);
            return new double[]{ lower * 100.0, 100.0 };
        }

        // Numerical binary search on cumulative binomial distribution
        double lower = findBetaRoot(k, n - k + 1, alpha / 2.0);
        double upper = findBetaRoot(k + 1, n - k, 1.0 - alpha / 2.0);

        return new double[]{ lower * 100.0, upper * 100.0 };
    }

    private static double findBetaRoot(int a, int b, double targetCdf) {
        double low = 0.0;
        double high = 1.0;
        for (int iter = 0; iter < 40; iter++) {
            double mid = (low + high) / 2.0;
            double cdf = betaCdf(mid, a, b);
            if (cdf < targetCdf) {
                low = mid;
            } else {
                high = mid;
            }
        }
        return (low + high) / 2.0;
    }

    /**
     * Regularized incomplete beta function I_x(a, b) via binomial expansion sum.
     */
    private static double betaCdf(double x, int a, int b) {
        if (x <= 0.0) return 0.0;
        if (x >= 1.0) return 1.0;
        int n = a + b - 1;
        double sum = 0.0;
        for (int j = a; j <= n; j++) {
            sum += binomialPdf(n, j, x);
        }
        return sum;
    }

    private static double binomialPdf(int n, int k, double p) {
        if (k < 0 || k > n) return 0.0;
        double logCoeff = logFactorial(n) - logFactorial(k) - logFactorial(n - k);
        double logProb = logCoeff + k * Math.log(p) + (n - k) * Math.log(1.0 - p);
        return Math.exp(logProb);
    }

    private static double logFactorial(int m) {
        double sum = 0.0;
        for (int i = 2; i <= m; i++) {
            sum += Math.log(i);
        }
        return sum;
    }

    /**
     * Computes Detection Error Trade-off (DET) curve points across varying threshold values.
     */
    public static List<DetPoint> computeDetCurve(List<PresentationResult> genuineResults, List<PresentationResult> attackResults) {
        List<DetPoint> det = new ArrayList<>();
        double[] thresholds = { 0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95 };

        int totalGenuine = genuineResults.size();
        int totalAttacks = attackResults.size();

        for (double th : thresholds) {
            int attacksAccepted = 0;
            for (PresentationResult a : attackResults) {
                if (a.finalDecision() == DecisionType.ACCEPTED || a.livenessScore() >= th) {
                    attacksAccepted++;
                }
            }
            double apcer = totalAttacks > 0 ? ((double) attacksAccepted / totalAttacks) * 100.0 : 0.0;

            int genuineRejected = 0;
            for (PresentationResult g : genuineResults) {
                if (g.finalDecision() != DecisionType.ACCEPTED || g.livenessScore() < th) {
                    genuineRejected++;
                }
            }
            double bpcer = totalGenuine > 0 ? ((double) genuineRejected / totalGenuine) * 100.0 : 0.0;

            det.add(new DetPoint(th, apcer, bpcer));
        }

        return det;
    }

    private static boolean isImageFile(String name) {
        String lower = name.toLowerCase();
        return lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".png");
    }

    private static File getSidecarFile(File imgFile) {
        String path = imgFile.getAbsolutePath();
        int dot = path.lastIndexOf('.');
        if (dot > 0) {
            String jsonPath = path.substring(0, dot) + ".json";
            return new File(jsonPath);
        }
        return null;
    }

    private static List<Point2D> parseSidecarPoints(File jsonFile) {
        try {
            JsonNode root = mapper.readTree(jsonFile);
            JsonNode lms = root.has("landmarks") ? root.get("landmarks") : root;
            if (lms.isArray()) {
                List<Point2D> pts = new ArrayList<>(lms.size());
                for (JsonNode pt : lms) {
                    if (pt.isArray() && pt.size() >= 2) {
                        pts.add(new Point2D((float) pt.get(0).asDouble(), (float) pt.get(1).asDouble()));
                    } else if (pt.isObject() && pt.has("x") && pt.has("y")) {
                        pts.add(new Point2D((float) pt.get("x").asDouble(), (float) pt.get("y").asDouble()));
                    }
                }
                return pts;
            }
        } catch (Exception ignored) {
        }
        return Collections.emptyList();
    }
}
