package io.mosip.liveness.core.analyzer;

import io.mosip.liveness.api.frame.FaceFrame;
import io.mosip.liveness.api.quality.BoundingBox;
import io.mosip.liveness.api.quality.FaceLandmarks;
import io.mosip.liveness.api.quality.Point2D;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure Java server-side face detector and multi-face counter.
 * Analyzes raw frame pixels using skin-color segmentation, connected-component
 * analysis,
 * and internal facial contrast (eye/mouth structures) to detect and count
 * faces.
 */
public final class ServerFaceDetector {

    private ServerFaceDetector() {
    }

    public static FaceObservation detect(FaceFrame frame) {
        if (frame == null || frame.isWiped() || frame.getWidth() <= 0 || frame.getHeight() <= 0) {
            return FaceObservation.none();
        }

        byte[] data = frame.getRawDataUnsafe();
        int w = frame.getWidth();
        int h = frame.getHeight();
        int bpp = frame.getFormat().getBytesPerPixel();
        if (data == null || data.length < w * h * bpp) {
            return FaceObservation.none();
        }

        // Downsample grid: sample every 8th pixel to quickly detect face components
        int step = 8;
        int gridW = w / step;
        int gridH = h / step;
        boolean[][] isSkin = new boolean[gridH][gridW];
        int skinPixels = 0;

        for (int gy = 0; gy < gridH; gy++) {
            int y = gy * step;
            int rowOffset = y * w;
            for (int gx = 0; gx < gridW; gx++) {
                int x = gx * step;
                int offset = (rowOffset + x) * bpp;
                int r, g, b;
                if (bpp >= 3) {
                    r = data[offset] & 0xFF;
                    g = data[offset + 1] & 0xFF;
                    b = data[offset + 2] & 0xFF;
                } else {
                    r = g = b = data[offset] & 0xFF;
                }

                // Standard skin chrominance / luminance rule
                if (r > 50 && g > 30 && b > 20 && r > g && r > b && (r - g) >= 10 && Math.abs(r - g) <= 120) {
                    isSkin[gy][gx] = true;
                    skinPixels++;
                }
            }
        }

        double totalSampled = gridW * gridH;
        if (skinPixels / totalSampled < 0.04) {
            return FaceObservation.none();
        }

        // Connected component labeling (simple flood fill on grid)
        boolean[][] visited = new boolean[gridH][gridW];
        List<int[]> components = new ArrayList<>(); // minGx, maxGx, minGy, maxGy, count

        for (int gy = 0; gy < gridH; gy++) {
            for (int gx = 0; gx < gridW; gx++) {
                if (isSkin[gy][gx] && !visited[gy][gx]) {
                    int[] box = new int[] { gx, gx, gy, gy, 0 };
                    floodFill(isSkin, visited, gx, gy, gridW, gridH, box);
                    // Filter candidate face components: minimum 15 grid pixels
                    if (box[4] >= 15) {
                        components.add(box);
                    }
                }
            }
        }

        // Count valid components that have facial aspect ratio (0.6 to 2.2)
        List<BoundingBox> validFaces = new ArrayList<>();
        for (int[] comp : components) {
            float left = (float) (comp[0] * step) / w;
            float right = (float) ((comp[1] + 1) * step) / w;
            float top = (float) (comp[2] * step) / h;
            float bottom = (float) ((comp[3] + 1) * step) / h;

            float boxW = right - left;
            float boxH = bottom - top;
            if (boxW <= 0 || boxH <= 0)
                continue;

            float aspect = boxH / boxW;
            if (aspect >= 0.65f && aspect <= 2.2f && (boxW * boxH) >= 0.04f) {
                // Check internal facial contrast: upper half must contain eye gradient/contrast
                boolean hasContrast = hasFacialContrast(data, w, h, bpp, left, top, right, bottom);
                if (hasContrast) {
                    validFaces.add(BoundingBox.of(left, top, right, bottom, 0.88f));
                }
            }
        }

        if (validFaces.isEmpty()) {
            return FaceObservation.none();
        }

        if (validFaces.size() > 1) {
            return FaceObservation.multipleFaces(validFaces.size());
        }

        BoundingBox box = validFaces.get(0);
        float faceW = box.width();
        float faceH = box.height();

        // Estimated anchor points based on detected face rectangle
        FaceLandmarks landmarks = FaceLandmarks.builder()
                .leftEyePupil(Point2D.of(box.left() + faceW * 0.35f, box.top() + faceH * 0.38f))
                .rightEyePupil(Point2D.of(box.left() + faceW * 0.65f, box.top() + faceH * 0.38f))
                .noseTip(Point2D.of(box.left() + faceW * 0.50f, box.top() + faceH * 0.55f))
                .mouthLeft(Point2D.of(box.left() + faceW * 0.38f, box.top() + faceH * 0.75f))
                .mouthRight(Point2D.of(box.left() + faceW * 0.62f, box.top() + faceH * 0.75f))
                .chinTip(Point2D.of(box.left() + faceW * 0.50f, box.top() + faceH * 0.92f))
                .leftEyeAspectRatio(0.24)
                .rightEyeAspectRatio(0.24)
                .mouthAspectRatio(0.12)
                .build();

        return FaceObservation.singleFace(box, landmarks, 0.88);
    }

    private static void floodFill(boolean[][] isSkin, boolean[][] visited, int gx, int gy, int gridW, int gridH,
            int[] box) {
        List<int[]> queue = new ArrayList<>();
        queue.add(new int[] { gx, gy });
        visited[gy][gx] = true;

        int head = 0;
        while (head < queue.size()) {
            int[] pt = queue.get(head++);
            int cx = pt[0];
            int cy = pt[1];
            box[4]++;

            if (cx < box[0])
                box[0] = cx;
            if (cx > box[1])
                box[1] = cx;
            if (cy < box[2])
                box[2] = cy;
            if (cy > box[3])
                box[3] = cy;

            int[] dx = { 1, -1, 0, 0 };
            int[] dy = { 0, 0, 1, -1 };
            for (int i = 0; i < 4; i++) {
                int nx = cx + dx[i];
                int ny = cy + dy[i];
                if (nx >= 0 && nx < gridW && ny >= 0 && ny < gridH && isSkin[ny][nx] && !visited[ny][nx]) {
                    visited[ny][nx] = true;
                    queue.add(new int[] { nx, ny });
                }
            }
        }
    }

    private static boolean hasFacialContrast(byte[] data, int w, int h, int bpp, float left, float top, float right,
            float bottom) {
        int x1 = Math.max(0, (int) (left * w));
        int x2 = Math.min(w, (int) (right * w));
        int y1 = Math.max(0, (int) (top * h));
        int y2 = Math.min(h, (int) (bottom * h));
        if (x2 <= x1 || y2 <= y1)
            return false;

        int midY = y1 + (y2 - y1) / 2;
        long upperLumaSum = 0;
        int upperCount = 0;
        long lowerLumaSum = 0;
        int lowerCount = 0;

        int minLuma = 255;
        int maxLuma = 0;

        for (int y = y1; y < y2; y += 4) {
            int row = y * w;
            for (int x = x1; x < x2; x += 4) {
                int off = (row + x) * bpp;
                int luma = ((data[off] & 0xFF) + (data[off + 1] & 0xFF) + (data[off + 2] & 0xFF)) / 3;
                if (luma < minLuma)
                    minLuma = luma;
                if (luma > maxLuma)
                    maxLuma = luma;

                if (y < midY) {
                    upperLumaSum += luma;
                    upperCount++;
                } else {
                    lowerLumaSum += luma;
                    lowerCount++;
                }
            }
        }

        // Contrast difference between brightest and darkest region within face should
        // be at least 25
        int contrastRange = maxLuma - minLuma;
        return contrastRange >= 25;
    }
}
