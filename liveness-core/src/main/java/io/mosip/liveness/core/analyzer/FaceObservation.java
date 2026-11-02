package io.mosip.liveness.core.analyzer;

import io.mosip.liveness.api.quality.BoundingBox;
import io.mosip.liveness.api.quality.FaceLandmarks;

/**
 * Observed face metadata extracted by landmark analyzer or face detector.
 */
public record FaceObservation(
        int faceCount,
        BoundingBox box,
        FaceLandmarks landmarks,
        double detectorConfidence
) {
    public FaceObservation {
        if (box == null && faceCount > 0) {
            box = BoundingBox.of(0.2f, 0.2f, 0.8f, 0.8f, (float) detectorConfidence);
        }
        if (landmarks == null) {
            landmarks = FaceLandmarks.builder().build();
        }
    }

    public static FaceObservation none() {
        return new FaceObservation(0, null, FaceLandmarks.builder().build(), 0.0);
    }

    public static FaceObservation singleFace(BoundingBox box, FaceLandmarks landmarks, double confidence) {
        return new FaceObservation(1, box, landmarks, confidence);
    }

    public static FaceObservation multipleFaces(int count) {
        return new FaceObservation(count, BoundingBox.of(0.1f, 0.1f, 0.9f, 0.9f, 0.9f), FaceLandmarks.builder().build(), 0.9);
    }
}
