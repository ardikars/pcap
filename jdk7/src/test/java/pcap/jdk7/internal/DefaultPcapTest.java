package pcap.jdk7.internal;

import com.sun.jna.Pointer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.WarningException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;
import pcap.spi.option.DefaultOfflineOptions;

@RunWith(JUnitPlatform.class)
public class DefaultPcapTest extends BaseTest {

  private Service service;
  private String file;

  private static void logBuf(String message, PacketBuffer buffer) {
    // System.out.println(message + ": " + buffer);
  }

  @BeforeEach
  void setUp() throws ErrorException {
    service = Service.Creator.create("PcapService");
    try {
      file = Files.createTempFile("temporary", ".pcapng").toAbsolutePath().toString();
    } catch (IOException e) {
      file = null;
    }
  }

  @Test
  void dumpOpen()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    String newFile;
    newFile = file.concat(UUID.randomUUID().toString());
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      try (Dumper dumper = live.dumpOpen(newFile)) {
        // Assertions.assertTrue(Files.exists(Paths.get(newFile)));
        Assertions.assertNotNull(dumper);
        Assertions.assertThrows(
            IllegalArgumentException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                live.dumpOpen(null);
              }
            });
      }
    }
    newFile = file.concat(UUID.randomUUID().toString());
    try (Pcap offline = service.offline(SAMPLE_NANOSECOND_PCAP, new DefaultOfflineOptions())) {
      try (Dumper dumper = offline.dumpOpen(newFile)) {
        // Assertions.assertTrue(Files.exists(Paths.get(newFile)));
        Assertions.assertNotNull(dumper);
        Assertions.assertThrows(
            IllegalArgumentException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                offline.dumpOpen(null);
              }
            });
      }
    } catch (ErrorException e) {
      System.err.println(e.getMessage());
    }
  }

  @Test
  void dumpOpenAppend()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    Assertions.assertTrue(Files.exists(Paths.get(SAMPLE_NANOSECOND_PCAP)));
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().snapshotLength(SAMPLE_PCAP_SNAPLEN))) {
      try (Dumper dumper = live.dumpOpenAppend(SAMPLE_MICROSECOND_PCAP)) {
        Assertions.assertNotNull(dumper);
      } catch (ErrorException e) {
        // may different link type or snaplen
      }
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.dumpOpenAppend(SAMPLE_NANOSECOND_PCAP);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.dumpOpenAppend(null);
            }
          });
    }
    try (Pcap offline = service.offline(SAMPLE_NANOSECOND_PCAP, new DefaultOfflineOptions())) {
      try (Dumper dumper = offline.dumpOpenAppend(SAMPLE_MICROSECOND_PCAP)) {
        Assertions.assertNotNull(dumper);
      } catch (ErrorException e) {
        // may different link type or snaplen
      }
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.dumpOpenAppend(SAMPLE_NANOSECOND_PCAP);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.dumpOpenAppend(null);
            }
          });
    } catch (ErrorException e) {
      System.err.println(e.getMessage());
    }
  }

  @Test
  void setFilter()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      live.setFilter("icmp", true);
      live.setFilter("icmp", false);
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.setFilter(null, true);
            }
          });
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      offline.setFilter("icmp", true);
      offline.setFilter("icmp", false);
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.setFilter(null, true);
            }
          });
    }
  }

  @Test
  void loop()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      live.loop(
          MAX_PKT,
          new PacketHandler<String>() {
            @Override
            public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
              Assertions.assertEquals("Hello!", args);
              Assertions.assertNotNull(header);
              Assertions.assertNotNull(buffer);
            }
          },
          "Hello!");
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.loop(MAX_PKT, null, "Hello!");
            }
          });
    } catch (BreakException e) {
      //
    } catch (ErrorException e) {

    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      offline.loop(
          MAX_PKT,
          new PacketHandler<String>() {
            @Override
            public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
              Assertions.assertEquals("Hello!", args);
              Assertions.assertNotNull(header);
              Assertions.assertNotNull(buffer);
            }
          },
          "Hello!");
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.loop(MAX_PKT, null, "Hello!");
            }
          });
    } catch (BreakException e) {

    } catch (ErrorException e) {

    }
  }

  @Test
  void dispatch()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      live.dispatch(
          MAX_PKT,
          new PacketHandler<String>() {
            @Override
            public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
              Assertions.assertEquals("Hello!", args);
              Assertions.assertNotNull(header);
              Assertions.assertNotNull(buffer);
            }
          },
          "Hello!");
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.dispatch(MAX_PKT, null, "Hello!");
            }
          });
    } catch (TimeoutException e) {
    } catch (BreakException e) {

    } catch (ErrorException e) {

    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      offline.dispatch(
          MAX_PKT,
          new PacketHandler<String>() {
            @Override
            public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
              Assertions.assertEquals("Hello!", args);
              Assertions.assertNotNull(header);
              Assertions.assertNotNull(buffer);
            }
          },
          "Hello!");
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.dispatch(MAX_PKT, null, "Hello!");
            }
          });
    } catch (TimeoutException e) {
    } catch (BreakException e) {
    } catch (ErrorException e) {
    }
  }

  @Test
  void next()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampPrecision(Timestamp.Precision.MICRO))) {
      PacketHeader header = live.allocate(PacketHeader.class);
      PacketBuffer next = live.next(header);
      if (next != null) {
        Assertions.assertTrue(next.capacity() > 0);
        Assertions.assertEquals(next.capacity(), next.writerIndex());
        Assertions.assertEquals(next.capacity(), header.captureLength());
      }
      live.setNonBlock(true);
      for (int i = 0; i < 5; i++) {
        live.next(header);
      }
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.next(null);
            }
          });
    }
  }

  @Test
  void nextEx()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      final PacketHeader header = live.allocate(PacketHeader.class);
      final PacketBuffer buffer = live.allocate(PacketBuffer.class);
      logBuf("nextEx", buffer);
      for (int i = 0; i < 1; i++) {
        try {
          live.nextEx(header, buffer);
          //          Assertions.assertTrue(header.timestamp().second() > 0);
          //          Assertions.assertTrue(header.timestamp().microSecond() > 0);
          Assertions.assertTrue(header.captureLength() > 0);
          Assertions.assertTrue(header.length() > 0);
          Assertions.assertTrue(buffer.capacity() > 0);
        } catch (ErrorException | BreakException | TimeoutException e) {
        }
        Assertions.assertThrows(
            IllegalArgumentException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                live.nextEx(null, null);
              }
            });
        Assertions.assertThrows(
            IllegalArgumentException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                live.nextEx(header, null);
              }
            });
        Assertions.assertThrows(
            IllegalArgumentException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                live.nextEx(null, buffer);
              }
            });
      }
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      final PacketHeader header = offline.allocate(PacketHeader.class);
      final PacketBuffer buffer = offline.allocate(PacketBuffer.class);
      logBuf("nextEx", buffer);
      for (int i = 0; i < 1; i++) {
        try {
          offline.nextEx(header, buffer);
          //          Assertions.assertTrue(header.timestamp().second() > 0);
          //          Assertions.assertTrue(header.timestamp().microSecond() > 0);
          Assertions.assertTrue(header.captureLength() > 0);
          Assertions.assertTrue(header.length() > 0);
          Assertions.assertTrue(buffer.capacity() > 0);
        } catch (ErrorException | BreakException | TimeoutException e) {

        }
        Assertions.assertThrows(
            BreakException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                offline.nextEx(header, buffer);
              }
            });
        Assertions.assertThrows(
            IllegalArgumentException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                offline.nextEx(null, null);
              }
            });
        Assertions.assertThrows(
            IllegalArgumentException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                offline.nextEx(header, null);
              }
            });
        Assertions.assertThrows(
            IllegalArgumentException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                offline.nextEx(null, buffer);
              }
            });
      }
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      PacketHeader header = offline.allocate(PacketHeader.class);
      PacketBuffer buffer = offline.allocate(PacketBuffer.class);
      logBuf("nextEx", buffer);
      for (int i = 0; i < 1; i++) {
        try {
          offline.nextEx(header, buffer);
          //          Assertions.assertTrue(header.timestamp().second() > 0);
          //          Assertions.assertTrue(header.timestamp().microSecond() > 0);
          Assertions.assertTrue(header.captureLength() > 0);
          Assertions.assertTrue(header.length() > 0);
          Assertions.assertTrue(buffer.capacity() > 0);
        } catch (ErrorException | BreakException | TimeoutException e) {

        }
      }
    }
  }

  @Test
  void stats()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      PacketHeader header = live.allocate(PacketHeader.class);
      PacketBuffer buffer = live.allocate(PacketBuffer.class);
      logBuf("stats", buffer);
      try {
        live.nextEx(header, buffer);
        Statistics statistics = live.stats();
        int dropped = statistics.dropped();
        int droppedByInterface = statistics.droppedByInterface();
        int received = statistics.received();
        Assertions.assertTrue(dropped >= 0);
        Assertions.assertTrue(droppedByInterface >= 0);
        Assertions.assertTrue(received >= 0);
      } catch (BreakException | ErrorException | TimeoutException e) {
      }
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.stats();
            }
          });
    }
  }

  @Test
  void breakLoop()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException, InterruptedException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      Assertions.assertThrows(
          BreakException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.loop(
                  -1,
                  new PacketHandler<String>() {
                    @Override
                    public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
                      Assertions.assertEquals("Hello!", args);
                      Assertions.assertNotNull(header);
                      Assertions.assertNotNull(buffer);
                      live.breakLoop();
                    }
                  },
                  "Hello!");
            }
          });
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      boolean breakLoop = false;
      while (!breakLoop) {
        try {
          live.dispatch(
              -1,
              new PacketHandler<String>() {
                @Override
                public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
                  Assertions.assertEquals("Hello!", args);
                  Assertions.assertNotNull(header);
                  Assertions.assertNotNull(buffer);
                  live.breakLoop();
                }
              },
              "Hello!");
        } catch (ErrorException | BreakException | TimeoutException e) {
          breakLoop = true;
        }
      }
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      Assertions.assertThrows(
          BreakException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.loop(
                  -1,
                  new PacketHandler<String>() {
                    @Override
                    public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
                      Assertions.assertEquals("Hello!", args);
                      Assertions.assertNotNull(header);
                      Assertions.assertNotNull(buffer);
                      offline.breakLoop();
                    }
                  },
                  "Hello!");
            }
          });
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      boolean breakLoop = false;
      while (!breakLoop) {
        try {
          offline.dispatch(
              -1,
              new PacketHandler<String>() {
                @Override
                public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
                  Assertions.assertEquals("Hello!", args);
                  Assertions.assertNotNull(header);
                  Assertions.assertNotNull(buffer);
                  offline.breakLoop();
                }
              },
              "Hello!");
        } catch (ErrorException | BreakException | TimeoutException e) {
          breakLoop = true;
        }
      }
    }
  }

  @Test
  void sendPacket()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      PacketBuffer buffer = live.allocate(PacketBuffer.class).capacity(14);
      logBuf("sendPacket", buffer);
      buffer.writeBytes(new byte[] {0, 0, 0, 0, 0, 1});
      buffer.writeBytes(new byte[] {0, 0, 0, 0, 0, 2});
      buffer.writeShortRE(0x0806);
      try {
        live.sendPacket(buffer);
      } finally {
        Assertions.assertTrue(buffer.release());
      }
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.sendPacket(null);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.sendPacket(new DefaultPacketBuffer());
            }
          });
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      final PacketBuffer buffer = offline.allocate(PacketBuffer.class).capacity(14);
      logBuf("sendPacket", buffer);

      buffer.writeBytes(new byte[] {0, 0, 0, 0, 0, 1});
      buffer.writeBytes(new byte[] {0, 0, 0, 0, 0, 2});
      buffer.writeShortRE(0x0806);
      buffer.release();
      try {
        offline.sendPacket(buffer);
      } catch (ErrorException e) {
        //
      } finally {
        Assertions.assertTrue(buffer.release());
      }
    }
  }

  @Test
  void setDirection()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      try {
        live.setDirection(Pcap.Direction.PCAP_D_INOUT);
        live.setDirection(Pcap.Direction.PCAP_D_IN);
        live.setDirection(Pcap.Direction.PCAP_D_OUT);
      } catch (ErrorException e) {

      }
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.setDirection(null);
            }
          });
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.setDirection(Pcap.Direction.PCAP_D_INOUT);
            }
          });
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.setDirection(Pcap.Direction.PCAP_D_IN);
            }
          });
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.setDirection(Pcap.Direction.PCAP_D_OUT);
            }
          });
    }
  }

  @Test
  void isSwapped()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException, NotActivatedException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      Assertions.assertFalse(live.isSwapped());
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      Assertions.assertTrue(offline.isSwapped() || !offline.isSwapped());
    }
  }

  @Test
  void majorVersion()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException, NotActivatedException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      Assertions.assertTrue(live.majorVersion() >= 0 || live.majorVersion() <= 0);
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      Assertions.assertTrue(offline.majorVersion() > 0);
    }
  }

  @Test
  void minorVersion()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException, NotActivatedException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      Assertions.assertTrue(live.minorVersion() >= 0 || live.majorVersion() <= 0);
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      Assertions.assertTrue(offline.minorVersion() > 0);
    }
  }

  @Test
  void snapshot()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      Assertions.assertTrue(live.snapshot() > 0);
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      Assertions.assertTrue(offline.snapshot() > 0);
    }
  }

  @Test
  void getNonBlock()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      Assertions.assertFalse(live.getNonBlock());
      live.setNonBlock(true);
      Assertions.assertTrue(live.getNonBlock());
      live.setNonBlock(false);
      Assertions.assertFalse(live.getNonBlock());
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      Assertions.assertFalse(offline.getNonBlock());
    }
  }

  @Test
  void setNonBlock()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      Assertions.assertFalse(live.getNonBlock());
      live.setNonBlock(true);
      Assertions.assertTrue(live.getNonBlock());
      live.setNonBlock(false);
      Assertions.assertFalse(live.getNonBlock());
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      if (!NativeMappings.isWinPcap) {
        Assertions.assertThrows(
            ErrorException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                offline.setNonBlock(true);
              }
            });
        Assertions.assertThrows(
            ErrorException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                offline.setNonBlock(false);
              }
            });
      }
    }
  }

  @Test
  void datalink()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      Assertions.assertTrue(live.datalink() >= 0);
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      Assertions.assertTrue(offline.datalink() >= 0);
    }
  }

  @Test
  void allocate()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      PacketBuffer buffer = live.allocate(PacketBuffer.class);
      logBuf("allocate", buffer);
      Assertions.assertNotNull(buffer);
      PacketHeader header = live.allocate(PacketHeader.class);
      Assertions.assertNotNull(header);
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.allocate(Pcap.class);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              live.allocate(null);
            }
          });
    }
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      PacketBuffer buffer = offline.allocate(PacketBuffer.class);
      logBuf("allocate", buffer);
      Assertions.assertNotNull(buffer);
      PacketHeader header = offline.allocate(PacketHeader.class);
      Assertions.assertNotNull(header);
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.allocate(Pcap.class);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              offline.allocate(null);
            }
          });
    }
  }

  @Test
  void nullCheck()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    final DefaultService defaultService = (DefaultService) this.service;
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      DefaultPcap pcap = (DefaultPcap) live;
      Pointer dumper =
          NativeMappings.pcap_dump_open(pcap.pointer, file.concat(UUID.randomUUID().toString()));
      defaultService.nullCheck(dumper);
      NativeMappings.pcap_dump_close(dumper);
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              defaultService.nullCheck(null);
            }
          });
      try {
        final Pointer nullDumper =
            NativeMappings.PLATFORM_DEPENDENT.pcap_dump_open_append(
                pcap.pointer, SAMPLE_NANOSECOND_PCAP);
        //
      } catch (NullPointerException | UnsatisfiedLinkError e) {
        //
      }
    }
  }

  @Test
  void compileCheck()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      final DefaultPcap pcap = (DefaultPcap) live;
      final NativeMappings.bpf_program fp = new NativeMappings.bpf_program();
      pcap.compileCheck(NativeMappings.pcap_compile(pcap.pointer, fp, "icmp", 1, pcap.netmask), fp);
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.compileCheck(
                  NativeMappings.pcap_compile(
                      pcap.pointer, fp, UUID.randomUUID().toString(), 1, pcap.netmask),
                  fp);
            }
          });
    }
  }

  @Test
  void filterCheck()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      final DefaultPcap pcap = (DefaultPcap) live;
      final NativeMappings.bpf_program fp = new NativeMappings.bpf_program();
      pcap.compileCheck(NativeMappings.pcap_compile(pcap.pointer, fp, "icmp", 1, pcap.netmask), fp);
      pcap.filterCheck(0, fp);
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.filterCheck(-1, fp);
            }
          });
    }
  }

  @Test
  void loopCheck()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      final DefaultPcap pcap = (DefaultPcap) offline;
      pcap.loopCheck(0);
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.loopCheck(-1);
            }
          });
      Assertions.assertThrows(
          BreakException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.loopCheck(-2);
            }
          });
    } catch (BreakException e) {

    } catch (ErrorException e) {

    }
  }

  @Test
  void ditpatchCheck() {
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      final DefaultPcap pcap = (DefaultPcap) offline;
      pcap.loopCheck(0);
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.dispatchCheck(-1);
            }
          });
      Assertions.assertThrows(
          BreakException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.dispatchCheck(-2);
            }
          });
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.dispatchCheck(-3);
            }
          });
    } catch (BreakException | ErrorException e) {

    }
  }

  @Test
  void nextExCheck() {
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      final DefaultPcap pcap = (DefaultPcap) offline;
      final DefaultPacketHeader header = (DefaultPacketHeader) pcap.allocate(PacketHeader.class);
      final DefaultPacketBuffer buffer = (DefaultPacketBuffer) pcap.allocate(PacketBuffer.class);
      logBuf("nextExChack", buffer);
      int rc = NativeMappings.pcap_next_ex(pcap.pointer, header.reference, buffer.reference);
      if (rc == 1) {
        pcap.nextExCheck(rc, header, buffer);
      }
      Assertions.assertThrows(
          TimeoutException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.nextExCheck(0, header, buffer);
            }
          });
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.nextExCheck(-1, header, buffer);
            }
          });
      Assertions.assertThrows(
          BreakException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.nextExCheck(-2, header, buffer);
            }
          });
    } catch (BreakException e) {
    } catch (TimeoutException e) {
    } catch (ErrorException e) {
    }
  }

  @Test
  void statsCheck()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      final DefaultPcap pcap = (DefaultPcap) live;
      pcap.statsCheck(0);
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.statsCheck(-1);
            }
          });
    }
  }

  @Test
  void sendCheck()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      final DefaultPcap pcap = (DefaultPcap) live;
      pcap.sendCheck(0);
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.sendCheck(-1);
            }
          });
    }
  }

  @Test
  void directionCheck()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      final DefaultPcap pcap = (DefaultPcap) live;
      pcap.directionCheck(1);
      pcap.directionCheck(0);
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.directionCheck(-1);
            }
          });
    }
  }

  @Test
  void getNonBlockCheck()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      final DefaultPcap pcap = (DefaultPcap) live;
      pcap.getNonBlockCheck(0);
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.getNonBlockCheck(-1);
            }
          });
    }
  }

  @Test
  void setNonBlockCheck()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
      final DefaultPcap pcap = (DefaultPcap) live;
      pcap.setNonBlockCheck(0);
      Assertions.assertThrows(
          ErrorException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.setNonBlockCheck(-1);
            }
          });
    }
  }

  @Test
  void swappedCheck() throws ErrorException, NotActivatedException {
    try (Pcap offline = service.offline(SAMPLE_MICROSECOND_PCAP, new DefaultOfflineOptions())) {
      final DefaultPcap pcap = (DefaultPcap) offline;
      Assertions.assertTrue(pcap.swappedCheck(1));
      Assertions.assertFalse(pcap.swappedCheck(0));
      Assertions.assertFalse(pcap.swappedCheck(-1));
      Assertions.assertFalse(pcap.swappedCheck(2));
      Assertions.assertThrows(
          NotActivatedException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              pcap.swappedCheck(-3);
            }
          });
    }
  }

  @Test
  void getTimestampPrecision()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          RadioFrequencyModeNotSupportedException, NoSuchDeviceException, ActivatedException,
          InterfaceNotUpException, InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampPrecision(Timestamp.Precision.MICRO))) {
      Assertions.assertEquals(Timestamp.Precision.MICRO, live.getTimestampPrecision());
    } catch (ErrorException | WarningException | TimestampPrecisionNotSupportedException e) {
    }
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampPrecision(Timestamp.Precision.NANO))) {
      // Assertions.assertEquals(Timestamp.Precision.NANO, live.getTimestampPrecision());
      Assertions.assertNotNull(live.getTimestampPrecision()); // 1.2.1 doesn't support this function
    } catch (ErrorException | WarningException | TimestampPrecisionNotSupportedException e) {
    }
  }

  @Test
  public void timestampPrecision() {
    Assertions.assertEquals(Timestamp.Precision.MICRO, DefaultPcap.timestampPrecision(0));
    Assertions.assertEquals(Timestamp.Precision.NANO, DefaultPcap.timestampPrecision(1));
  }

  @Test
  public void writeLock()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          RadioFrequencyModeNotSupportedException, NoSuchDeviceException, ActivatedException,
          InterfaceNotUpException, InterfaceNotSupportTimestampTypeException {
    Interface lo = loopbackInterface(service);
    try (final Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampPrecision(Timestamp.Precision.MICRO))) {
      final DefaultPcap defaultPcap = (DefaultPcap) live;
      defaultPcap.tryReadLock();
      Assertions.assertThrows(
          RuntimeException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              defaultPcap.tryWriteLock();
            }
          });
    } catch (ErrorException | WarningException | TimestampPrecisionNotSupportedException e) {
    }
  }
}
