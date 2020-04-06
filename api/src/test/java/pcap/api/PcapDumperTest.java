package pcap.api;

import java.io.IOException;
import java.nio.file.Files;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledOnJre;
import org.junit.jupiter.api.condition.JRE;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Dumper;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;

@EnabledOnJre(JRE.JAVA_14)
// @RunWith(JUnitPlatform.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class PcapDumperTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapDumperTest.class);
  private static final int MAX_PACKET = 10;
  private static final String FILE;

  @Test
  @Order(1)
  public void liveDumpTest()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = Pcaps.lookupInterface();
    Assertions.assertNotNull(source);
    Pcap pcap = Pcaps.live(new PcapLive(source));
    Dumper dumper = pcap.dumpOpen(FILE);
    Assertions.assertNotNull(dumper);
    LOGGER.info("File: {}", FILE);
    try {
      pcap.loop(
          MAX_PACKET,
          (args, header, buffer) -> {
            Assertions.assertNotNull(buffer.buffer());
            Assertions.assertNotNull(header);
            Assertions.assertNotNull(buffer);
            Assertions.assertNotEquals(header.captureLength(), 0);
            Assertions.assertNotEquals(header.length(), 0);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertNotEquals(header.timestamp().microSecond(), 0);
            Assertions.assertNotEquals(header.timestamp().second(), 0L);
            args.dump(header, buffer);
            args.flush();
            Assertions.assertNotEquals(args.position(), 0);
          },
          dumper);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    dumper.close();
    Assertions.assertNotNull(pcap);
    pcap.close();
  }

  @Test
  @Order(2)
  public void liveDumpAppendTest()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = Pcaps.lookupInterface();
    Assertions.assertNotNull(source);
    Pcap pcap = Pcaps.live(new PcapLive(source));
    Dumper dumper = pcap.dumpOpenAppend(FILE);
    Assertions.assertNotNull(dumper);
    LOGGER.info("File: {}", FILE);
    try {
      pcap.loop(
          MAX_PACKET,
          (args, header, buffer) -> {
            Assertions.assertNotNull(buffer.buffer());
            Assertions.assertNotNull(header);
            Assertions.assertNotNull(buffer);
            Assertions.assertNotEquals(header.captureLength(), 0);
            Assertions.assertNotEquals(header.length(), 0);
            Assertions.assertNotNull(header.timestamp());
            Assertions.assertNotEquals(header.timestamp().microSecond(), 0);
            Assertions.assertNotEquals(header.timestamp().second(), 0L);
            args.dump(header, buffer);
            args.flush();
            Assertions.assertNotEquals(args.position(), 0);
          },
          dumper);
    } catch (BreakException e) {
      LOGGER.warn(e);
    }
    dumper.close();
    Assertions.assertNotNull(pcap);
    pcap.close();
  }

  static {
    String file;
    try {
      file = Files.createTempFile("temporary", ".pcapng").toAbsolutePath().toString();
    } catch (IOException e) {
      file = null;
    }
    FILE = file;
  }
}
