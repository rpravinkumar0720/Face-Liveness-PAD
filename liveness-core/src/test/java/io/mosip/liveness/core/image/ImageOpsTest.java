package io.mosip.liveness.core.image;

import io.mosip.liveness.api.frame.FaceFrame;
import io.mosip.liveness.api.frame.PixelFormat;
import io.mosip.liveness.api.quality.BoundingBox;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ImageOpsTest {

    private static FaceFrame createSyntheticFrame(int width, int height, byte[] rgbData) {
        return FaceFrame.wrap(rgbData, width, height, PixelFormat.RGB_888, System.nanoTime(), 1L, "SYNTH_DEVICE", 0);
    }

    private static byte[] createUniformRgb(int width, int height, int r, int g, int b) {
        byte[] data = new byte[width * height * 3];
        for (int i = 0; i < width * height; i++) {
            data[i * 3] = (byte) r;
            data[i * 3 + 1] = (byte) g;
            data[i * 3 + 2] = (byte) b;
        }
        return data;
    }

    private static byte[] createCheckerboardRgb(int width, int height, int blockSize, int val1, int val2) {
        byte[] data = new byte[width * height * 3];
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int check = ((x / blockSize) + (y / blockSize)) % 2;
                int val = check == 0 ? val1 : val2;
                int idx = (y * width + x) * 3;
                data[idx] = (byte) val;
                data[idx + 1] = (byte) val;
                data[idx + 2] = (byte) val;
            }
        }
        return data;
    }

    @Test
    @DisplayName("toGrayscale and meanLuma on uniform frames")
    void testToGrayscaleAndMeanLuma() {
        int w = 100, h = 100;
        // Mid-gray image (128, 128, 128)
        FaceFrame frame = createSyntheticFrame(w, h, createUniformRgb(w, h, 128, 128, 128));
        byte[] gray = ImageOps.toGrayscale(frame);
        assertThat(gray).hasSize(w * h);
        assertThat(gray[0] & 0xFF).isEqualTo(128);

        double luma = ImageOps.meanLuma(frame);
        assertThat(luma).isBetween(0.49, 0.51);
    }

    @Test
    @DisplayName("laplacianVariance correctly distinguishes sharp checkerboard from blank frame")
    void testLaplacianVariance() {
        int w = 120, h = 120;
        BoundingBox roi = BoundingBox.of(0.1f, 0.1f, 0.9f, 0.9f, 1.0f);

        // Sharp high-contrast checkerboard
        FaceFrame sharpFrame = createSyntheticFrame(w, h, createCheckerboardRgb(w, h, 4, 10, 240));
        double sharpVar = ImageOps.laplacianVariance(sharpFrame, roi);
        assertThat(sharpVar).isGreaterThan(500.0);

        // Completely uniform frame has 0 variance
        FaceFrame blankFrame = createSyntheticFrame(w, h, createUniformRgb(w, h, 100, 100, 100));
        double blankVar = ImageOps.laplacianVariance(blankFrame, roi);
        assertThat(blankVar).isEqualTo(0.0);
    }

    @Test
    @DisplayName("cropRegion and downscale produce expected dimensions and values")
    void testCropAndDownscale() {
        int w = 80, h = 80;
        byte[] gray = ImageOps.toGrayscale(createSyntheticFrame(w, h, createCheckerboardRgb(w, h, 8, 50, 200)));

        BoundingBox box = BoundingBox.of(0.25f, 0.25f, 0.75f, 0.75f, 1.0f);
        byte[] cropped = ImageOps.cropRegion(gray, w, h, box);
        assertThat(cropped).hasSize(40 * 40);

        byte[] downscaled = ImageOps.downscale(cropped, 40, 40, 16, 16);
        assertThat(downscaled).hasSize(16 * 16);
    }

    @Test
    @DisplayName("specularHighlightRatio identifies near-saturated pixels")
    void testSpecularHighlightRatio() {
        int w = 64, h = 64;
        BoundingBox box = BoundingBox.of(0.0f, 0.0f, 1.0f, 1.0f, 1.0f);

        FaceFrame normal = createSyntheticFrame(w, h, createUniformRgb(w, h, 120, 120, 120));
        assertThat(ImageOps.specularHighlightRatio(normal, box)).isEqualTo(0.0);

        FaceFrame saturated = createSyntheticFrame(w, h, createUniformRgb(w, h, 250, 250, 250));
        assertThat(ImageOps.specularHighlightRatio(saturated, box)).isEqualTo(1.0);
    }

    @Test
    @DisplayName("colorChannelStats detects mean and saturation variations")
    void testColorChannelStats() {
        int w = 50, h = 50;
        BoundingBox box = BoundingBox.of(0.0f, 0.0f, 1.0f, 1.0f, 1.0f);

        // Highly saturated pure red
        FaceFrame redFrame = createSyntheticFrame(w, h, createUniformRgb(w, h, 220, 0, 0));
        ImageOps.ColorStats stats = ImageOps.colorChannelStats(redFrame, box);
        assertThat(stats.rMean()).isCloseTo(220.0, org.assertj.core.data.Offset.offset(1.0));
        assertThat(stats.gMean()).isEqualTo(0.0);
        assertThat(stats.meanSaturation()).isCloseTo(1.0, org.assertj.core.data.Offset.offset(0.01));
    }

    @Test
    @DisplayName("highFrequencyEnergyRatio detects periodic patterns in checkerboard")
    void testHighFrequencyEnergyRatio() {
        int w = 64, h = 64;
        BoundingBox box = BoundingBox.of(0.0f, 0.0f, 1.0f, 1.0f, 1.0f);

        FaceFrame periodicFrame = createSyntheticFrame(w, h, createCheckerboardRgb(w, h, 4, 30, 220));
        double periodicRatio = ImageOps.highFrequencyEnergyRatio(periodicFrame, box);

        FaceFrame uniformFrame = createSyntheticFrame(w, h, createUniformRgb(w, h, 128, 128, 128));
        double uniformRatio = ImageOps.highFrequencyEnergyRatio(uniformFrame, box);

        assertThat(periodicRatio).isGreaterThan(uniformRatio);
    }
}
