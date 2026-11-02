package io.mosip.liveness.core.analyzer;

import io.mosip.liveness.api.quality.BoundingBox;
import io.mosip.liveness.api.quality.FaceLandmarks;

import java.util.Locale;

/**
 * Validates client-provided landmarks against server-side detections.
 * Evaluates bounding-box IoU, center alignment, eye-centre distance, and pose discrepancies.
 * Flags genuine landmark forgery attacks while accommodating natural segmentation variance.
 */
public final class LandmarkCrossValidator {

    public record LandmarkValidationResult(
            boolean valid,
            String reason,
            double iou,
            double eyeDistance
    ) {
        public static LandmarkValidationResult success(double iou, double eyeDistance) {
            return new LandmarkValidationResult(true, "Landmarks consistent with server detection", iou, eyeDistance);
        }

        public static LandmarkValidationResult failure(String reason, double iou, double eyeDistance) {
            return new LandmarkValidationResult(false, reason, iou, eyeDistance);
        }
    }

    private LandmarkCrossValidator() {
    }

    /**
     * Cross-validates client observation against server observation.
     */
    public static LandmarkValidationResult validate(FaceObservation clientObs, FaceObservation serverObs) {
        if (clientObs == null || clientObs.faceCount() <= 0) {
            return LandmarkValidationResult.success(1.0, 0.0);
        }

        // If server detected no face while client claimed a face:
        if (serverObs == null || serverObs.faceCount() <= 0) {
            return LandmarkValidationResult.failure("Server detected 0 faces while client claimed face presence", 0.0, 1.0);
        }

        // If server detected multiple faces while client claimed single:
        if (serverObs.faceCount() > 1 && clientObs.faceCount() == 1) {
            return LandmarkValidationResult.failure("Server detected multiple faces (" + serverObs.faceCount() + ")", 0.0, 1.0);
        }

        // 1. Bounding box IoU and spatial alignment check
        BoundingBox cb = clientObs.box();
        BoundingBox sb = serverObs.box();
        double iou = 1.0;
        if (cb != null && sb != null) {
            iou = computeIoU(cb, sb);
            if (iou < 0.20) {
                double centerDist = Math.hypot(cb.centerX() - sb.centerX(), cb.centerY() - sb.centerY());
                double overlap = computeOverlapCoeff(cb, sb);
                // If centers are significantly misaligned or spatial overlap is negligible, flag attack
                if (centerDist > 0.25 || overlap < 0.25) {
                    return LandmarkValidationResult.failure(
                            String.format(Locale.ROOT, "Bounding box IoU below threshold: %.3f (min 0.200)", iou),
                            iou, 1.0
                    );
                }
            }
        }

        // 2. Eye center pupil distance check
        FaceLandmarks cl = clientObs.landmarks();
        FaceLandmarks sl = serverObs.landmarks();
        double eyeDist = 0.0;
        if (cl != null && sl != null && cl.leftEyePupil() != null && sl.leftEyePupil() != null) {
            eyeDist = cl.leftEyePupil().distanceTo(sl.leftEyePupil());
            if (eyeDist > 0.35) {
                return LandmarkValidationResult.failure(
                        String.format(Locale.ROOT, "Eye pupil distance exceeded: %.3f (max 0.350)", eyeDist),
                        iou, eyeDist
                );
            }
        }

        // 3. Pose delta check
        if (cl != null && sl != null) {
            double yawDelta = Math.abs(cl.estimatedYawDegrees() - sl.estimatedYawDegrees());
            if (yawDelta > 35.0) {
                return LandmarkValidationResult.failure(
                        String.format(Locale.ROOT, "Pose yaw discrepancy exceeded: %.1f deg (max 35.0 deg)", yawDelta),
                        iou, eyeDist
                );
            }
        }

        return LandmarkValidationResult.success(iou, eyeDist);
    }

    /**
     * Computes intersection-over-union (IoU) of two bounding boxes.
     */
    public static double computeIoU(BoundingBox a, BoundingBox b) {
        if (a == null || b == null) return 0.0;

        float xLeft = Math.max(a.left(), b.left());
        float yTop = Math.max(a.top(), b.top());
        float xRight = Math.min(a.right(), b.right());
        float yBottom = Math.min(a.bottom(), b.bottom());

        if (xRight <= xLeft || yBottom <= yTop) {
            return 0.0;
        }

        float intersectionArea = (xRight - xLeft) * (yBottom - yTop);
        float areaA = a.area();
        float areaB = b.area();
        float unionArea = areaA + areaB - intersectionArea;

        return unionArea > 0 ? (double) intersectionArea / unionArea : 0.0;
    }

    /**
     * Computes overlap coefficient (intersection over minimum area) of two bounding boxes.
     */
    public static double computeOverlapCoeff(BoundingBox a, BoundingBox b) {
        if (a == null || b == null) return 0.0;

        float xLeft = Math.max(a.left(), b.left());
        float yTop = Math.max(a.top(), b.top());
        float xRight = Math.min(a.right(), b.right());
        float yBottom = Math.min(a.bottom(), b.bottom());

        if (xRight <= xLeft || yBottom <= yTop) {
            return 0.0;
        }

        float intersectionArea = (xRight - xLeft) * (yBottom - yTop);
        float minArea = Math.min(a.area(), b.area());

        return minArea > 0 ? (double) intersectionArea / minArea : 0.0;
    }
}
