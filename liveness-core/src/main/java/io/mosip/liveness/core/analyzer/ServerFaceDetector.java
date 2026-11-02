package io.mosip.liveness.core.analyzer;

import io.mosip.liveness.api.frame.FaceFrame;
import io.mosip.liveness.api.quality.BoundingBox;
import io.mosip.liveness.api.quality.FaceLandmarks;
import io.mosip.liveness.api.quality.Point2D;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure Java server-side face detector, landmark corroborator, and multi-face counter.
 * Analyzes raw frame pixels using illumination-invariant YCbCr/RGB skin segmentation,
 * connected-component clustering, internal facial contrast, and targeted client-mesh verification.
 */
public final class ServerFaceDetector {

    private ServerFaceDetector() {
    }

    public static FaceObservation detect(FaceFrame frame) {
        return detect(frame, null);
    }

    public static FaceObservation detect(FaceFrame frame, FaceObservation clientHint) {
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

        // Targeted validation when client asserts a detected face
        if (clientHint != null && clientHint.faceCount() > 0 && clientHint.box() != null) {
            BoundingBox cb = clientHint.box();
            if (cb.width() >= 0.08f && cb.height() >= 0.08f) {
                boolean clientBoxVerified = validateClaimedFaceBox(data, w, h, bpp, cb);
                if (clientBoxVerified) {
                    // Check for secondary distinct face outside the claimed box
                    int secondaryFaces = countSecondaryFaces(data, w, h, bpp, cb);
                    if (secondaryFaces > 0) {
                        return FaceObservation.multipleFaces(1 + secondaryFaces);
                    }
                    return FaceObservation.singleFace(cb, clientHint.landmarks(), 0.95);
                }
            }
        }

        // Global autonomous face detection across full frame
        return detectGlobal(data, w, h, bpp);
    }

    /**
     * Verifies that the client-claimed bounding box contains genuine human face pixels
     * (skin chrominance distribution and internal facial contrast/gradient).
     */
    public static boolean validateClaimedFaceBox(byte[] data, int w, int h, int bpp, BoundingBox box) {
        int x1 = Math.max(0, box.pixelLeft(w));
        int y1 = Math.max(0, box.pixelTop(h));
        int x2 = Math.min(w, box.pixelLeft(w) + box.pixelWidth(w));
        int y2 = Math.min(h, box.pixelTop(h) + box.pixelHeight(h));
        if (x2 <= x1 || y2 <= y1) {
            return false;
        }

        int skinCount = 0;
        int totalSampled = 0;
        int minLuma = 255;
        int maxLuma = 0;

        for (int y = y1; y < y2; y += 4) {
            int row = y * w;
            for (int x = x1; x < x2; x += 4) {
                int off = (row + x) * bpp;
                int r, g, b;
                if (bpp >= 3) {
                    r = data[off] & 0xFF;
                    g = data[off + 1] & 0xFF;
                    b = data[off + 2] & 0xFF;
                } else {
                    r = g = b = data[off] & 0xFF;
                }

                int luma = (299 * r + 587 * g + 114 * b) / 1000;
                if (luma < minLuma) minLuma = luma;
                if (luma > maxLuma) maxLuma = luma;

                if (isSkin(r, g, b)) {
                    skinCount++;
                }
                totalSampled++;
            }
        }

        if (totalSampled < 10) return false;
        double skinFraction = (double) skinCount / totalSampled;
        int contrastRange = maxLuma - minLuma;

        // A genuine face contains both sufficient skin coverage and internal facial contrast (eyes, mouth, shading)
        return skinFraction >= 0.15 && contrastRange >= 20;
    }

    private static int countSecondaryFaces(byte[] data, int w, int h, int bpp, BoundingBox primaryBox) {
        int step = 8;
        int gridW = w / step;
        int gridH = h / step;
        boolean[][] isSkin = new boolean[gridH][gridW];

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
                if (isSkin(r, g, b)) {
                    isSkin[gy][gx] = true;
                }
            }
        }

        boolean[][] visited = new boolean[gridH][gridW];
        int secondaryCount = 0;

        for (int gy = 0; gy < gridH; gy++) {
            for (int gx = 0; gx < gridW; gx++) {
                if (isSkin[gy][gx] && !visited[gy][gx]) {
                    int[] box = new int[] { gx, gx, gy, gy, 0 };
                    floodFill(isSkin, visited, gx, gy, gridW, gridH, box);
                    if (box[4] >= 25) {
                        float left = (float) (box[0] * step) / w;
                        float right = (float) ((box[1] + 1) * step) / w;
                        float top = (float) (box[2] * step) / h;
                        float bottom = (float) ((box[3] + 1) * step) / h;
                        float boxW = right - left;
                        float boxH = bottom - top;
                        if (boxW > 0 && boxH > 0) {
                            float aspect = boxH / boxW;
                            if (aspect >= 0.65f && aspect <= 2.2f && (boxW * boxH) >= 0.04f) {
                                BoundingBox cand = BoundingBox.of(left, top, right, bottom, 0.85f);
                                double centerDist = Math.hypot(cand.centerX() - primaryBox.centerX(), cand.centerY() - primaryBox.centerY());
                                // Secondary face must be spatially separated and not vertically below primary (torso/neck)
                                boolean isTorsoOrNeck = (cand.top() >= primaryBox.centerY()) && Math.abs(cand.centerX() - primaryBox.centerX()) < 0.15;
                                if (centerDist > 0.25 && !isTorsoOrNeck && hasFacialContrast(data, w, h, bpp, left, top, right, bottom)) {
                                    secondaryCount++;
                                }
                            }
                        }
                    }
                }
            }
        }
        return secondaryCount;
    }

    private static FaceObservation detectGlobal(byte[] data, int w, int h, int bpp) {
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
                if (isSkin(r, g, b)) {
                    isSkin[gy][gx] = true;
                    skinPixels++;
                }
            }
        }

        double totalSampled = gridW * gridH;
        if (skinPixels / totalSampled < 0.03) {
            return FaceObservation.none();
        }

        boolean[][] visited = new boolean[gridH][gridW];
        List<int[]> components = new ArrayList<>();

        for (int gy = 0; gy < gridH; gy++) {
            for (int gx = 0; gx < gridW; gx++) {
                if (isSkin[gy][gx] && !visited[gy][gx]) {
                    int[] box = new int[] { gx, gx, gy, gy, 0 };
                    floodFill(isSkin, visited, gx, gy, gridW, gridH, box);
                    if (box[4] >= 15) {
                        components.add(box);
                    }
                }
            }
        }

        List<BoundingBox> validFaces = new ArrayList<>();
        for (int[] comp : components) {
            float left = (float) (comp[0] * step) / w;
            float right = (float) ((comp[1] + 1) * step) / w;
            float top = (float) (comp[2] * step) / h;
            float bottom = (float) ((comp[3] + 1) * step) / h;

            float boxW = right - left;
            float boxH = bottom - top;
            if (boxW <= 0 || boxH <= 0) continue;

            float aspect = boxH / boxW;
            if (aspect >= 0.60f && aspect <= 2.2f && (boxW * boxH) >= 0.03f) {
                if (hasFacialContrast(data, w, h, bpp, left, top, right, bottom)) {
                    validFaces.add(BoundingBox.of(left, top, right, bottom, 0.88f));
                }
            }
        }

        if (validFaces.isEmpty()) {
            return FaceObservation.none();
        }

        // Filter out neck/torso components that lie directly under an upper face component
        List<BoundingBox> distinctFaces = new ArrayList<>();
        for (BoundingBox f : validFaces) {
            boolean isSubTorso = false;
            for (BoundingBox other : validFaces) {
                if (f != other && f.top() > other.top() && Math.abs(f.centerX() - other.centerX()) < 0.15) {
                    isSubTorso = true;
                    break;
                }
            }
            if (!isSubTorso) {
                distinctFaces.add(f);
            }
        }

        if (distinctFaces.isEmpty()) {
            distinctFaces.add(validFaces.get(0));
        }

        if (distinctFaces.size() > 1) {
            return FaceObservation.multipleFaces(distinctFaces.size());
        }

        BoundingBox box = distinctFaces.get(0);
        float faceW = box.width();
        float faceH = box.height();

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

    /**
     * Illumination-invariant multi-color-space skin classifier.
     * Evaluates RGB and YCbCr chrominance clusters (Fitzpatrick I-VI).
     */
    public static boolean isSkin(int r, int g, int b) {
        // RGB rule
        boolean rgbSkin = (r > 40 && g > 25 && b > 15)
                && (r > b)
                && (r >= g || (g - r) <= 15)
                && Math.abs(r - g) <= 120;

        // YCbCr chrominance cluster rule
        int y = (299 * r + 587 * g + 114 * b) / 1000;
        int cb = (-169 * r - 331 * g + 500 * b + 128000) / 1000;
        int cr = (500 * r - 419 * g - 81 * b + 128000) / 1000;
        boolean ycbcrSkin = (y >= 25 && y <= 245) && (cb >= 75 && cb <= 135) && (cr >= 130 && cr <= 180);

        return rgbSkin || ycbcrSkin;
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

            if (cx < box[0]) box[0] = cx;
            if (cx > box[1]) box[1] = cx;
            if (cy < box[2]) box[2] = cy;
            if (cy > box[3]) box[3] = cy;

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

        int minLuma = 255;
        int maxLuma = 0;

        for (int y = y1; y < y2; y += 4) {
            int row = y * w;
            for (int x = x1; x < x2; x += 4) {
                int off = (row + x) * bpp;
                int luma = ((data[off] & 0xFF) + (data[off + 1] & 0xFF) + (data[off + 2] & 0xFF)) / 3;
                if (luma < minLuma) minLuma = luma;
                if (luma > maxLuma) maxLuma = luma;
            }
        }

        // Contrast difference between brightest and darkest region within face should be at least 25
        int contrastRange = maxLuma - minLuma;
        return contrastRange >= 25;
    }
}
