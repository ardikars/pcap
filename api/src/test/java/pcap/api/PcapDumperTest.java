package pcap.api;

import java.io.IOException;
import java.nio.file.Files;
import org.junit.jupiter.api.*;
import pcap.api.internal.PcapDumper;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Dumper;
import pcap.spi.Interface;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class PcapDumperTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapDumper.class);
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
            args.dump(header, buffer);
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
            args.dump(header, buffer);
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
