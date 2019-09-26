package pcap.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Timestamp;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;

import java.util.concurrent.atomic.AtomicInteger;

@RunWith(JUnitPlatform.class)
public class PcapOfflineTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(PcapOfflineTest.class);

    private static final int MAX_PACKET = 10;
    private static final String FILTER = "ip";
    private static final String FILE = "../.resources/sample.pcapng";

    @Test
    public void offlineTest() throws ErrorException {
        Pcap pcap = Pcaps.offline(new PcapOffline(FILE)
            .timestampPrecision(Timestamp.Precision.MICRO)
        );
        Assertions.assertNotNull(pcap);
        pcap.close();
    }

    @Test
    public void offlineLoopTest() throws ErrorException {
        Pcap pcap = Pcaps.offline(new PcapOffline(FILE));
        Assertions.assertNotNull(pcap);
        try {
            pcap.loop(
                    MAX_PACKET,
                    (args, header, buffer) -> {
                        Assertions.assertEquals(args, MAX_PACKET);
                        Assertions.assertNotNull(buffer);
                        Assertions.assertNotNull(buffer.buffer());
                        Assertions.assertNotNull(header);
                        Assertions.assertNotEquals(header.captureLength(), 0);
                        Assertions.assertNotEquals(header.length(), 0);
                        Assertions.assertNotNull(header.timestamp());
                        Assertions.assertNotEquals(header.timestamp().microSecond(), 0);
                        Assertions.assertNotEquals(header.timestamp().second(), 0L);
                    },
                    MAX_PACKET);
        } catch (BreakException e) {
            LOGGER.warn(e);
        }
        pcap.close();
    }

    @Test
    public void offlineFilterTest() throws ErrorException {
        Pcap pcap = Pcaps.offline(new PcapOffline(FILE));
        Assertions.assertNotNull(pcap);
        pcap.setFilter(FILTER, true);
        try {
            pcap.loop(
                    MAX_PACKET,
                    (args, header, buffer) -> {
                        Assertions.assertEquals(args, MAX_PACKET);
                        Assertions.assertNotNull(buffer);
                        Assertions.assertNotNull(buffer.buffer());
                        Assertions.assertNotNull(header);
                        Assertions.assertNotEquals(header.captureLength(), 0);
                        Assertions.assertNotEquals(header.length(), 0);
                        Assertions.assertNotNull(header.timestamp());
                        Assertions.assertNotEquals(header.timestamp().microSecond(), 0);
                        Assertions.assertNotEquals(header.timestamp().second(), 0L);
                    },
                    MAX_PACKET);
        } catch (BreakException e) {
            LOGGER.warn(e);
        }
        pcap.close();
    }

    @Test
    public void liveLoopBreakTest() throws ErrorException {
        Pcap pcap = Pcaps.offline(new PcapOffline(FILE));
        Assertions.assertNotNull(pcap);
        try {
            AtomicInteger counter = new AtomicInteger();
            pcap.loop(
                    MAX_PACKET,
                    (args, header, buffer) -> {
                        if (counter.incrementAndGet() == args / 2) {
                            pcap.breakLoop();
                        }
                        Assertions.assertEquals(args, MAX_PACKET);
                        Assertions.assertNotNull(buffer);
                        Assertions.assertNotNull(buffer.buffer());
                        Assertions.assertNotNull(header);
                        Assertions.assertNotEquals(header.captureLength(), 0);
                        Assertions.assertNotEquals(header.length(), 0);
                        Assertions.assertNotNull(header.timestamp());
                        Assertions.assertNotEquals(header.timestamp().microSecond(), 0);
                        Assertions.assertNotEquals(header.timestamp().second(), 0L);
                    },
                    MAX_PACKET);
        } catch (BreakException e) {
            LOGGER.warn(e);
        }
        pcap.close();
    }
}
