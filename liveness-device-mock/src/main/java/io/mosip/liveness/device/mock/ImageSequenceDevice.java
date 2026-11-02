package io.mosip.liveness.device.mock;

import io.mosip.liveness.api.device.DeviceCapabilities;
import io.mosip.liveness.api.device.DeviceStatus;
import io.mosip.liveness.api.device.DeviceStatusListener;
import io.mosip.liveness.api.device.FaceCaptureDevice;
import io.mosip.liveness.api.device.Resolution;
import io.mosip.liveness.api.device.SecurityLevel;
import io.mosip.liveness.api.frame.FaceFrame;
import io.mosip.liveness.api.frame.PixelFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Mock FaceCaptureDevice that reads still images or sequence directories and streams them
 * at a configurable frame rate on a background daemon thread.
 */
public class ImageSequenceDevice implements FaceCaptureDevice {

    private static final Logger log = LoggerFactory.getLogger(ImageSequenceDevice.class);

    private final String deviceId;
    private final File sequenceDir;
    private final int targetFps;
    private final boolean loop;

    private final List<DeviceStatusListener> listeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean streaming = new AtomicBoolean(false);
    private final AtomicBoolean connected = new AtomicBoolean(false);

    private final List<byte[]> cachedFrameData = new ArrayList<>();
    private int frameWidth = 640;
    private int frameHeight = 480;

    private Thread streamThread;
    private volatile FaceFrame lastFrame = null;
    private long sequenceCounter = 0L;

    public ImageSequenceDevice(File sequenceDir) {
        this("MOCK_CAM_01", sequenceDir, 15, true);
    }

    public ImageSequenceDevice(String deviceId, File sequenceDir, int targetFps, boolean loop) {
        this.deviceId = Objects.requireNonNull(deviceId, "deviceId cannot be null");
        this.sequenceDir = sequenceDir;
        this.targetFps = Math.max(1, Math.min(60, targetFps));
        this.loop = loop;
    }

    /**
     * Constructor accepting in-memory frames for test fixtures without disk access.
     */
    public ImageSequenceDevice(String deviceId, List<FaceFrame> frames, int targetFps, boolean loop) {
        this.deviceId = Objects.requireNonNull(deviceId, "deviceId cannot be null");
        this.sequenceDir = null;
        this.targetFps = Math.max(1, Math.min(60, targetFps));
        this.loop = loop;

        if (frames != null && !frames.isEmpty()) {
            this.frameWidth = frames.get(0).getWidth();
            this.frameHeight = frames.get(0).getHeight();
            for (FaceFrame f : frames) {
                cachedFrameData.add(f.getDataCopy());
            }
        }
    }

    @Override
    public synchronized void connect() {
        if (connected.get()) return;

        if (sequenceDir != null && sequenceDir.exists() && sequenceDir.isDirectory()) {
            File[] files = sequenceDir.listFiles((dir, name) -> {
                String lower = name.toLowerCase();
                return lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".png");
            });

            if (files != null && files.length > 0) {
                Arrays.sort(files, Comparator.comparing(File::getName));
                cachedFrameData.clear();
                for (File file : files) {
                    try {
                        BufferedImage img = ImageIO.read(file);
                        if (img != null) {
                            this.frameWidth = img.getWidth();
                            this.frameHeight = img.getHeight();
                            cachedFrameData.add(bufferedImageToRgb(img));
                        }
                    } catch (IOException e) {
                        log.warn("Failed to load mock frame: {}", file.getName(), e);
                    }
                }
            }
        }

        if (cachedFrameData.isEmpty()) {
            // Generate fallback default synthetic pattern
            cachedFrameData.add(createSyntheticFallback(frameWidth, frameHeight));
        }

        connected.set(true);
        notifyStatus(DeviceStatus.CONNECTED);
    }

    @Override
    public synchronized void disconnect() {
        stopStream();
        if (connected.getAndSet(false)) {
            notifyStatus(DeviceStatus.DISCONNECTED);
        }
    }

    @Override
    public synchronized void startStream(Consumer<FaceFrame> frameConsumer) {
        Objects.requireNonNull(frameConsumer, "frameConsumer cannot be null");
        if (!connected.get()) {
            connect();
        }

        if (streaming.get()) {
            return;
        }
        streaming.set(true);
        notifyStatus(DeviceStatus.STREAMING);

        long sleepMillis = 1000L / targetFps;

        streamThread = new Thread(() -> {
            int frameIdx = 0;
            while (streaming.get() && !Thread.currentThread().isInterrupted()) {
                if (cachedFrameData.isEmpty()) break;

                byte[] rawData = cachedFrameData.get(frameIdx);
                // Create frame copy
                FaceFrame frame = FaceFrame.wrap(
                        Arrays.copyOf(rawData, rawData.length),
                        frameWidth,
                        frameHeight,
                        PixelFormat.RGB_888,
                        System.nanoTime(),
                        ++sequenceCounter,
                        deviceId,
                        0
                );
                lastFrame = frame;

                try {
                    frameConsumer.accept(frame);
                } catch (Exception e) {
                    log.error("Exception in mock frame consumer", e);
                }

                frameIdx++;
                if (frameIdx >= cachedFrameData.size()) {
                    if (loop) {
                        frameIdx = 0;
                    } else {
                        break;
                    }
                }

                try {
                    Thread.sleep(sleepMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            streaming.set(false);
        }, "mock-stream-" + deviceId);

        streamThread.setDaemon(true);
        streamThread.start();
    }

    @Override
    public synchronized void stopStream() {
        if (streaming.getAndSet(false)) {
            if (streamThread != null) {
                streamThread.interrupt();
                streamThread = null;
            }
            notifyStatus(DeviceStatus.CONNECTED);
        }
    }

    @Override
    public FaceFrame captureStill() {
        if (!connected.get()) {
            connect();
        }
        if (lastFrame != null && !lastFrame.isWiped()) {
            return new FaceFrame(
                    lastFrame.getDataCopy(),
                    lastFrame.getWidth(),
                    lastFrame.getHeight(),
                    lastFrame.getFormat(),
                    System.nanoTime(),
                    ++sequenceCounter,
                    deviceId,
                    0
            );
        }
        byte[] data = cachedFrameData.isEmpty() ? createSyntheticFallback(frameWidth, frameHeight) : cachedFrameData.get(0);
        return new FaceFrame(
                Arrays.copyOf(data, data.length),
                frameWidth,
                frameHeight,
                PixelFormat.RGB_888,
                System.nanoTime(),
                ++sequenceCounter,
                deviceId,
                0
        );
    }

    @Override
    public DeviceCapabilities getCapabilities() {
        return DeviceCapabilities.builder()
                .deviceId(deviceId)
                .modelName("Mock Image Sequence Streamer")
                .vendorName("MOSIP Reference")
                .securityLevel(SecurityLevel.L0)
                .supportedResolutions(List.of(new Resolution(frameWidth, frameHeight)))
                .maxFps(targetFps)
                .supportedFormats(Set.of(PixelFormat.RGB_888))
                .hasHardwareCrypto(false)
                .hasInfrared(false)
                .build();
    }

    private volatile DeviceStatus currentStatus = DeviceStatus.DISCONNECTED;

    @Override
    public DeviceStatus getStatus() {
        if (streaming.get()) return DeviceStatus.STREAMING;
        if (connected.get()) return DeviceStatus.CONNECTED;
        return DeviceStatus.DISCONNECTED;
    }

    @Override
    public void addStatusListener(DeviceStatusListener listener) {
        if (listener != null) listeners.add(listener);
    }

    @Override
    public void removeStatusListener(DeviceStatusListener listener) {
        if (listener != null) listeners.remove(listener);
    }

    private synchronized void notifyStatus(DeviceStatus newStatus) {
        DeviceStatus old = currentStatus;
        currentStatus = newStatus;
        for (DeviceStatusListener l : listeners) {
            try {
                l.onStatusChanged(this, old, newStatus, "Status transitioned from " + old + " to " + newStatus);
            } catch (Exception e) {
                log.warn("Error notifying status listener", e);
            }
        }
    }

    private static byte[] bufferedImageToRgb(BufferedImage img) {
        int w = img.getWidth();
        int h = img.getHeight();
        byte[] rgb = new byte[w * h * 3];
        int idx = 0;
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int pixel = img.getRGB(x, y);
                rgb[idx++] = (byte) ((pixel >> 16) & 0xFF); // R
                rgb[idx++] = (byte) ((pixel >> 8) & 0xFF);  // G
                rgb[idx++] = (byte) (pixel & 0xFF);         // B
            }
        }
        return rgb;
    }

    private static byte[] createSyntheticFallback(int w, int h) {
        byte[] data = new byte[w * h * 3];
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int idx = (y * w + x) * 3;
                data[idx] = (byte) 180;
                data[idx + 1] = (byte) 130;
                data[idx + 2] = (byte) 100;
            }
        }
        return data;
    }
}
