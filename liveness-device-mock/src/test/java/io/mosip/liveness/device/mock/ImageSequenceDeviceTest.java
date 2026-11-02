package io.mosip.liveness.device.mock;

import io.mosip.liveness.api.device.DeviceCapabilities;
import io.mosip.liveness.api.device.DeviceStatus;
import io.mosip.liveness.api.device.DeviceStatusListener;
import io.mosip.liveness.api.device.SecurityLevel;
import io.mosip.liveness.api.frame.FaceFrame;
import io.mosip.liveness.api.frame.PixelFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class ImageSequenceDeviceTest {

    private static FaceFrame createMockFrame(int w, int h) {
        byte[] data = new byte[w * h * 3];
        return FaceFrame.wrap(data, w, h, PixelFormat.RGB_888, System.nanoTime(), 1L, "MOCK_01", 0);
    }

    @Test
    @DisplayName("Device connects, reports L0 security level and notifies status listeners")
    void testConnectAndCapabilities() {
        try (ImageSequenceDevice device = new ImageSequenceDevice("TEST_MOCK_DEV", List.of(createMockFrame(320, 240)), 30, true)) {
            AtomicReference<DeviceStatus> reportedStatus = new AtomicReference<>();
            DeviceStatusListener listener = (d, oldStatus, newStatus, msg) -> reportedStatus.set(newStatus);
            device.addStatusListener(listener);

            device.connect();
            assertThat(device.getStatus()).isEqualTo(DeviceStatus.CONNECTED);
            assertThat(reportedStatus.get()).isEqualTo(DeviceStatus.CONNECTED);

            DeviceCapabilities caps = device.getCapabilities();
            assertThat(caps.deviceId()).isEqualTo("TEST_MOCK_DEV");
            assertThat(caps.securityLevel()).isEqualTo(SecurityLevel.L0);
            assertThat(caps.supportedFormats()).contains(PixelFormat.RGB_888);

            device.disconnect();
            assertThat(device.getStatus()).isEqualTo(DeviceStatus.DISCONNECTED);
            assertThat(reportedStatus.get()).isEqualTo(DeviceStatus.DISCONNECTED);
        }
    }

    @Test
    @DisplayName("startStream streams frames to consumer and captureStill returns latest")
    void testStreamingAndCaptureStill() throws InterruptedException {
        try (ImageSequenceDevice device = new ImageSequenceDevice("STREAM_DEV", List.of(createMockFrame(100, 100)), 20, true)) {
            device.connect();

            CountDownLatch latch = new CountDownLatch(3);
            List<FaceFrame> received = new ArrayList<>();

            device.startStream(frame -> {
                received.add(frame);
                latch.countDown();
            });

            boolean completed = latch.await(2, TimeUnit.SECONDS);
            device.stopStream();

            assertThat(completed).isTrue();
            assertThat(received.size()).isGreaterThanOrEqualTo(3);

            FaceFrame still = device.captureStill();
            assertThat(still).isNotNull();
            assertThat(still.getWidth()).isEqualTo(100);
            assertThat(still.getHeight()).isEqualTo(100);

            device.disconnect();
        }
    }
}
