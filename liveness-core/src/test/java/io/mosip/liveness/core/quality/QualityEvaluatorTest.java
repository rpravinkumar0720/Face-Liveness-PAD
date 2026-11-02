package io.mosip.liveness.core.quality;

import io.mosip.liveness.api.frame.FaceFrame;
import io.mosip.liveness.api.frame.PixelFormat;
import io.mosip.liveness.api.quality.BoundingBox;
import io.mosip.liveness.api.quality.FaceLandmarks;
import io.mosip.liveness.api.quality.FaceQuality;
import io.mosip.liveness.api.quality.QualityFailureReason;
import io.mosip.liveness.core.analyzer.FaceObservation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class QualityEvaluatorTest {

    private static FaceFrame createSharpCompliantFrame(int width, int height, int luma) {
        byte[] data = new byte[width * height * 3];
        // Create high-frequency texture around center so Laplacian variance >= 80
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int noise = ((x % 2 == 0) ^ (y % 2 == 0)) ? 30 : -30;
                int v = Math.min(240, Math.max(15, luma + noise));
                int idx = (y * width + x) * 3;
                data[idx] = (byte) v;
                data[idx + 1] = (byte) v;
                data[idx + 2] = (byte) v;
            }
        }
        return FaceFrame.wrap(data, width, height, PixelFormat.RGB_888, System.nanoTime(), 1L, "TEST_DEVICE", 0);
    }

    private static FaceObservation createCompliantObservation() {
        BoundingBox box = BoundingBox.of(0.2f, 0.2f, 0.7f, 0.8f, 0.95f); // area = 0.5 * 0.6 = 0.30 (compliant 0.15..0.75)
        FaceLandmarks landmarks = FaceLandmarks.builder()
                .leftEyeAspectRatio(0.32)
                .rightEyeAspectRatio(0.31)
                .mouthAspectRatio(0.12)
                .estimatedYawDegrees(2.0)
                .estimatedPitchDegrees(-3.0)
                .estimatedRollDegrees(1.5)
                .build();
        return FaceObservation.singleFace(box, landmarks, 0.95);
    }

    @Test
    @DisplayName("Compliant observation and frame meets all ISO 19794-5 quality gates")
    void testCompliantQuality() {
        FaceFrame frame = createSharpCompliantFrame(120, 120, 130);
        FaceObservation obs = createCompliantObservation();

        FaceQuality quality = QualityEvaluator.evaluate(frame, obs);
        assertThat(quality.isCompliant()).isTrue();
        assertThat(quality.qualityFailures()).isEmpty();
        assertThat(QualityEvaluator.getPrimaryGuidance(quality.qualityFailures())).contains("good");
    }

    @Test
    @DisplayName("No face detected triggers NO_FACE_DETECTED")
    void testNoFaceDetected() {
        FaceFrame frame = createSharpCompliantFrame(100, 100, 130);
        FaceQuality quality = QualityEvaluator.evaluate(frame, FaceObservation.none());

        assertThat(quality.isCompliant()).isFalse();
        assertThat(quality.qualityFailures()).contains(QualityFailureReason.NO_FACE_DETECTED);
        assertThat(QualityEvaluator.getPrimaryGuidance(quality.qualityFailures())).contains("No face detected");
    }

    @Test
    @DisplayName("Multiple faces detected triggers MULTIPLE_FACES_DETECTED")
    void testMultipleFacesDetected() {
        FaceFrame frame = createSharpCompliantFrame(100, 100, 130);
        FaceQuality quality = QualityEvaluator.evaluate(frame, FaceObservation.multipleFaces(2));

        assertThat(quality.isCompliant()).isFalse();
        assertThat(quality.qualityFailures()).contains(QualityFailureReason.MULTIPLE_FACES_DETECTED);
        assertThat(QualityEvaluator.getPrimaryGuidance(quality.qualityFailures())).contains("Multiple faces");
    }

    @Test
    @DisplayName("Face area below 0.15 triggers FACE_TOO_SMALL")
    void testFaceTooSmall() {
        FaceFrame frame = createSharpCompliantFrame(100, 100, 130);
        BoundingBox tinyBox = BoundingBox.of(0.4f, 0.4f, 0.6f, 0.6f, 0.9f); // area = 0.04 < 0.15
        FaceObservation obs = new FaceObservation(1, tinyBox, FaceLandmarks.builder().build(), 0.9);

        FaceQuality quality = QualityEvaluator.evaluate(frame, obs);
        assertThat(quality.qualityFailures()).contains(QualityFailureReason.FACE_TOO_SMALL);
        assertThat(QualityEvaluator.getPrimaryGuidance(quality.qualityFailures())).contains("closer");
    }

    @Test
    @DisplayName("Face area above 0.75 triggers FACE_TOO_CLOSE")
    void testFaceTooClose() {
        FaceFrame frame = createSharpCompliantFrame(100, 100, 130);
        BoundingBox hugeBox = BoundingBox.of(0.05f, 0.05f, 0.95f, 0.95f, 0.9f); // area = 0.81 > 0.75
        FaceObservation obs = new FaceObservation(1, hugeBox, FaceLandmarks.builder().build(), 0.9);

        FaceQuality quality = QualityEvaluator.evaluate(frame, obs);
        assertThat(quality.qualityFailures()).contains(QualityFailureReason.FACE_TOO_CLOSE);
        assertThat(QualityEvaluator.getPrimaryGuidance(quality.qualityFailures())).contains("back");
    }

    @Test
    @DisplayName("Pose exceeding 15 degrees triggers pose failure reasons")
    void testPoseExceeded() {
        FaceFrame frame = createSharpCompliantFrame(100, 100, 130);
        BoundingBox box = BoundingBox.of(0.2f, 0.2f, 0.7f, 0.8f, 0.9f);

        FaceLandmarks yawLandmarks = FaceLandmarks.builder().estimatedYawDegrees(22.0).build();
        FaceQuality qYaw = QualityEvaluator.evaluate(frame, FaceObservation.singleFace(box, yawLandmarks, 0.9));
        assertThat(qYaw.qualityFailures()).contains(QualityFailureReason.POSE_YAW_EXCEEDED);

        FaceLandmarks pitchLandmarks = FaceLandmarks.builder().estimatedPitchDegrees(-19.0).build();
        FaceQuality qPitch = QualityEvaluator.evaluate(frame, FaceObservation.singleFace(box, pitchLandmarks, 0.9));
        assertThat(qPitch.qualityFailures()).contains(QualityFailureReason.POSE_PITCH_EXCEEDED);

        FaceLandmarks rollLandmarks = FaceLandmarks.builder().estimatedRollDegrees(18.0).build();
        FaceQuality qRoll = QualityEvaluator.evaluate(frame, FaceObservation.singleFace(box, rollLandmarks, 0.9));
        assertThat(qRoll.qualityFailures()).contains(QualityFailureReason.POSE_ROLL_EXCEEDED);
    }

    @Test
    @DisplayName("Under and over illumination triggers TOO_DARK and TOO_BRIGHT")
    void testIlluminationFailures() {
        BoundingBox box = BoundingBox.of(0.2f, 0.2f, 0.7f, 0.8f, 0.9f);
        FaceObservation obs = createCompliantObservation();

        // Dark frame: luma 20/255 = 0.078 < 0.20
        FaceFrame darkFrame = createSharpCompliantFrame(100, 100, 20);
        FaceQuality qDark = QualityEvaluator.evaluate(darkFrame, obs);
        assertThat(qDark.qualityFailures()).contains(QualityFailureReason.TOO_DARK);

        // Bright frame: luma 235/255 = 0.92 > 0.85
        FaceFrame brightFrame = createSharpCompliantFrame(100, 100, 235);
        FaceQuality qBright = QualityEvaluator.evaluate(brightFrame, obs);
        assertThat(qBright.qualityFailures()).contains(QualityFailureReason.TOO_BRIGHT);
    }

    @Test
    @DisplayName("Low Laplacian variance triggers BLURRY")
    void testBlurryFailure() {
        // Uniform color -> variance = 0 < 80
        byte[] flatData = new byte[100 * 100 * 3];
        java.util.Arrays.fill(flatData, (byte) 120);
        FaceFrame flatFrame = FaceFrame.wrap(flatData, 100, 100, PixelFormat.RGB_888, System.nanoTime(), 1L, "DEV", 0);

        FaceQuality quality = QualityEvaluator.evaluate(flatFrame, createCompliantObservation());
        assertThat(quality.qualityFailures()).contains(QualityFailureReason.BLURRY);
        assertThat(QualityEvaluator.getPrimaryGuidance(quality.qualityFailures())).contains("blurry");
    }

    @Test
    @DisplayName("Closed eyes and open mouth trigger EYES_CLOSED and MOUTH_OPEN")
    void testEyesAndMouthFailures() {
        FaceFrame frame = createSharpCompliantFrame(100, 100, 130);
        BoundingBox box = BoundingBox.of(0.2f, 0.2f, 0.7f, 0.8f, 0.9f);

        FaceLandmarks eyesClosed = FaceLandmarks.builder()
                .leftEyeAspectRatio(0.08)
                .rightEyeAspectRatio(0.07)
                .build();
        FaceQuality qEyes = QualityEvaluator.evaluate(frame, FaceObservation.singleFace(box, eyesClosed, 0.9));
        assertThat(qEyes.qualityFailures()).contains(QualityFailureReason.EYES_CLOSED);

        FaceLandmarks mouthOpen = FaceLandmarks.builder()
                .mouthAspectRatio(0.45)
                .build();
        FaceQuality qMouth = QualityEvaluator.evaluate(frame, FaceObservation.singleFace(box, mouthOpen, 0.9));
        assertThat(qMouth.qualityFailures()).contains(QualityFailureReason.MOUTH_OPEN);
    }

    @Test
    @DisplayName("Priority order selects NO_FACE before BLURRY or LIGHTING")
    void testPriorityOrder() {
        Set<QualityFailureReason> multiple = EnumSet.of(
                QualityFailureReason.BLURRY,
                QualityFailureReason.TOO_DARK,
                QualityFailureReason.NO_FACE_DETECTED
        );
        String guidance = QualityEvaluator.getPrimaryGuidance(multiple);
        assertThat(guidance).isEqualTo(QualityFailureReason.NO_FACE_DETECTED.getGuidanceMessage());
    }
}
