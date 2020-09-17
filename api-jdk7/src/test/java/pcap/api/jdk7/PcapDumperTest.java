package pcap.api.jdk7;

import java.io.IOException;
import java.nio.file.Files;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.api.BaseTest;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
public class PcapDumperTest extends BaseTest {

  private Service service;
  private String file;

  @BeforeEach
  public void setUp() throws ErrorException {
    service = Service.Creator.create("PcapService");
    try {
      file = Files.createTempFile("temporary", ".pcapng").toAbsolutePath().toString();
    } catch (IOException e) {
      file = null;
    }
  }

  @Test
  public void dump()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException, BreakException {
    Interface source = loopbackInterface(service);
    try (Pcap live = service.live(source, new DefaultLiveOptions())) {
      try (Dumper dumper = live.dumpOpen(file.concat(UUID.randomUUID().toString()))) {
        live.loop(
            1,
            new PacketHandler<Dumper>() {
              @Override
              public void gotPacket(Dumper args, PacketHeader header, PacketBuffer buffer) {
                Assertions.assertNull(args);
                Assertions.assertNotNull(header);
                Assertions.assertNotNull(buffer);
                Assertions.assertTrue(header.timestamp().second() > 0);
                Assertions.assertTrue(header.timestamp().microSecond() > 0);
                Assertions.assertTrue(header.captureLength() > 0);
                Assertions.assertTrue(header.length() > 0);
                Assertions.assertTrue(buffer.capacity() > 0);
                dumper.dump(header, buffer);
                dumper.flush();
                Assertions.assertTrue(dumper.position() > 0);
              }
            },
            null);
      }
    }
  }
}
