package io.mosip.liveness.core.passive;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Calibrated Logistic-Regression Fusion model for multi-heuristic PAD.
 * Replaces uncalibrated linear weighting with a data-fitted logistic sigmoid function
 * and strict multi-vector veto rules (e.g. >= 2 failing screen indicators).
 * Pure Java 17, zero external dependencies.
 */
public final class LogisticFusionModel {

    private static final Logger log = LoggerFactory.getLogger(LogisticFusionModel.class);

    public static final String DEFAULT_MODEL_RESOURCE = "/models/fusion_model_v1.json";

    private final String version;
    private final double intercept;
    private final Map<String, Double> weights;
    private final double screenThreshold;
    private final int screenMinFailures;
    private final double printThreshold;
    private final int printMinFailures;
    private final int totalMinFailures;

    public record FusionResult(
            double livenessScore,
            double attackScore,
            boolean hardVeto,
            String vetoCategory
    ) {}

    public LogisticFusionModel(String version,
                               double intercept,
                               Map<String, Double> weights,
                               double screenThreshold,
                               int screenMinFailures,
                               double printThreshold,
                               int printMinFailures,
                               int totalMinFailures) {
        this.version = version != null ? version : "1.0.0";
        this.intercept = intercept;
        this.weights = Map.copyOf(weights);
        this.screenThreshold = screenThreshold;
        this.screenMinFailures = screenMinFailures;
        this.printThreshold = printThreshold;
        this.printMinFailures = printMinFailures;
        this.totalMinFailures = totalMinFailures;
    }

    public static LogisticFusionModel loadDefault() {
        return loadFromResource(DEFAULT_MODEL_RESOURCE);
    }

    public static LogisticFusionModel loadFromResource(String resourcePath) {
        try (InputStream in = LogisticFusionModel.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                log.warn("Fusion model resource {} not found; using fallback calibrated defaults", resourcePath);
                return createFallbackModel();
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return parseJson(sb.toString());
        } catch (Exception e) {
            log.warn("Failed to load fusion model from {}: {}; using fallback", resourcePath, e.getMessage());
            return createFallbackModel();
        }
    }

    public static LogisticFusionModel createFallbackModel() {
        Map<String, Double> w = new LinkedHashMap<>();
        w.put("microMotion", 2.20);
        w.put("moire", 2.10);
        w.put("specular", 1.90);
        w.put("texture", 1.80);
        w.put("border", 1.60);
        w.put("timing", 2.50);
        w.put("consistency", 1.70);
        w.put("mask3d", 1.80);
        return new LogisticFusionModel("1.0.0-fallback", -6.50, w, 0.20, 2, 0.20, 2, 3);
    }

    /**
     * Minimal pure-Java parser for fusion model JSON.
     */
    private static LogisticFusionModel parseJson(String json) {
        String version = extractString(json, "version", "1.0.0");
        double intercept = extractDouble(json, "intercept", -6.50);

        Map<String, Double> weights = new LinkedHashMap<>();
        Pattern weightsBlockPattern = Pattern.compile("\"weights\"\\s*:\\s*\\{([^}]+)\\}");
        Matcher blockMatcher = weightsBlockPattern.matcher(json);
        if (blockMatcher.find()) {
            String block = blockMatcher.group(1);
            Pattern entryPattern = Pattern.compile("\"([a-zA-Z0-9_]+)\"\\s*:\\s*([-+]?[0-9]*\\.?[0-9]+)");
            Matcher entryMatcher = entryPattern.matcher(block);
            while (entryMatcher.find()) {
                weights.put(entryMatcher.group(1), Double.parseDouble(entryMatcher.group(2)));
            }
        }
        if (weights.isEmpty()) {
            weights = createFallbackModel().weights();
        }

        double screenThreshold = extractDouble(json, "screenThreshold", 0.20);
        int screenMinFailures = (int) Math.round(extractDouble(json, "screenMinFailures", 2.0));
        double printThreshold = extractDouble(json, "printThreshold", 0.20);
        int printMinFailures = (int) Math.round(extractDouble(json, "printMinFailures", 2.0));
        int totalMinFailures = (int) Math.round(extractDouble(json, "totalMinFailures", 3.0));

        return new LogisticFusionModel(version, intercept, weights, screenThreshold, screenMinFailures,
                printThreshold, printMinFailures, totalMinFailures);
    }

    private static String extractString(String json, String key, String defaultVal) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : defaultVal;
    }

    private static double extractDouble(String json, String key, double defaultVal) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*([-+]?[0-9]*\\.?[0-9]+)");
        Matcher m = p.matcher(json);
        return m.find() ? Double.parseDouble(m.group(1)) : defaultVal;
    }

    /**
     * Evaluates multi-heuristic scores with veto rules and logistic sigmoid blending.
     */
    public FusionResult evaluate(Map<String, Double> heuristics) {
        if (heuristics == null || heuristics.isEmpty()) {
            return new FusionResult(0.0, 1.0, true, "EMPTY");
        }

        // Count independent failure vectors
        int screenFailures = 0;
        if (heuristics.getOrDefault("moire", 1.0) < screenThreshold) screenFailures++;
        if (heuristics.getOrDefault("specular", 1.0) < screenThreshold) screenFailures++;
        if (heuristics.getOrDefault("border", 1.0) < screenThreshold) screenFailures++;
        if (heuristics.getOrDefault("timing", 1.0) < screenThreshold) screenFailures++;

        int printFailures = 0;
        if (heuristics.getOrDefault("microMotion", 1.0) < printThreshold) printFailures++;
        if (heuristics.getOrDefault("texture", 1.0) < printThreshold) printFailures++;

        int maskFailures = 0;
        if (heuristics.getOrDefault("mask3d", 1.0) < 0.20) maskFailures++;

        int totalFailures = screenFailures + printFailures + maskFailures;

        boolean hardVeto = false;
        String vetoCategory = null;

        if (screenFailures >= screenMinFailures) {
            hardVeto = true;
            vetoCategory = "SCREEN_REPLAY";
        } else if (heuristics.getOrDefault("timing", 1.0) < 0.10) {
            hardVeto = true;
            vetoCategory = "VIDEO_INJECTION";
        } else if (heuristics.getOrDefault("microMotion", 1.0) < 0.10 || printFailures >= printMinFailures) {
            hardVeto = true;
            vetoCategory = "PRINT_ATTACK";
        } else if (maskFailures >= 1 && (totalFailures >= 2 || heuristics.getOrDefault("mask3d", 1.0) < 0.12)) {
            hardVeto = true;
            vetoCategory = "MASK_3D";
        } else if (totalFailures >= totalMinFailures) {
            hardVeto = true;
            vetoCategory = "UNKNOWN_ATTACK";
        }

        if (hardVeto) {
            return new FusionResult(0.05, 0.95, true, vetoCategory);
        }

        // Logistic sigmoid combination: z = w0 + sum(wi * xi)
        double z = intercept;
        for (Map.Entry<String, Double> entry : weights.entrySet()) {
            double score = heuristics.getOrDefault(entry.getKey(), 0.90);
            z += entry.getValue() * score;
        }

        double liveness = 1.0 / (1.0 + Math.exp(-z));
        liveness = Math.max(0.0, Math.min(1.0, liveness));
        double attack = 1.0 - liveness;

        return new FusionResult(liveness, attack, false, null);
    }

    public String version() { return version; }
    public double intercept() { return intercept; }
    public Map<String, Double> weights() { return weights; }
    public double screenThreshold() { return screenThreshold; }
    public int screenMinFailures() { return screenMinFailures; }
    public double printThreshold() { return printThreshold; }
    public int printMinFailures() { return printMinFailures; }
    public int totalMinFailures() { return totalMinFailures; }
}
