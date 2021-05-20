/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
class DefaultPcapDumperTest extends BaseTest {

  private Service service;
  private String file;

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
  void dump()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = loopbackInterface(service);
    try (Pcap live = service.live(source, new DefaultLiveOptions())) {
      String newFile = file.concat(UUID.randomUUID().toString());
      try (final Dumper dumper = live.dumpOpen(newFile)) {
        live.loop(
            1,
            new PacketHandler<Dumper>() {
              @Override
              public void gotPacket(
                  final Dumper args, final PacketHeader header, final PacketBuffer buffer) {
                Assertions.assertNull(args);
                Assertions.assertNotNull(header);
                Assertions.assertNotNull(buffer);
                Assertions.assertTrue(header.captureLength() > 0);
                Assertions.assertTrue(header.length() > 0);
                Assertions.assertTrue(buffer.capacity() > 0);
                Assertions.assertTrue(dumper.position() > 0);
                dumper.dump(header, buffer);
                dumper.flush();

                final DefaultPacketBuffer packetBuffer = (DefaultPacketBuffer) buffer;
                Assertions.assertThrows(
                    IllegalArgumentException.class,
                    new Executable() {
                      @Override
                      public void execute() throws Throwable {
                        packetBuffer.readerIndex(packetBuffer.readerIndex() + 1);
                        dumper.dump(header, buffer);
                      }
                    });
                packetBuffer.readerIndex(packetBuffer.readerIndex() - 1);

                Assertions.assertThrows(
                    IllegalArgumentException.class,
                    new Executable() {
                      @Override
                      public void execute() throws Throwable {
                        dumper.dump(header, new DefaultPacketBuffer(null, null, 0L, 0L, 0L));
                      }
                    });
                Assertions.assertThrows(
                    IllegalArgumentException.class,
                    new Executable() {
                      @Override
                      public void execute() throws Throwable {
                        dumper.dump(null, buffer);
                      }
                    });
                Assertions.assertThrows(
                    IllegalArgumentException.class,
                    new Executable() {
                      @Override
                      public void execute() throws Throwable {
                        dumper.dump(header, null);
                      }
                    });
                Assertions.assertThrows(
                    IllegalArgumentException.class,
                    new Executable() {
                      @Override
                      public void execute() throws Throwable {
                        dumper.dump(null, null);
                      }
                    });
              }
            },
            null);
        try (Dumper append = live.dumpOpenAppend(newFile)) {
          //
        } catch (UnsatisfiedLinkError e) {

        }
      } catch (BreakException | ErrorException e) {

      }
    }
  }

  @Test
  void equalsAndHashCode()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Interface source = loopbackInterface(service);
    try (Pcap live = service.live(source, new DefaultLiveOptions())) {
      String newFile = file.concat(UUID.randomUUID().toString());
      String newFile1 = file.concat(UUID.randomUUID().toString());
      final DefaultDumper dumper = (DefaultDumper) live.dumpOpen(newFile);
      final DefaultDumper dumper1 = (DefaultDumper) live.dumpOpen(newFile1);
      Assertions.assertTrue(dumper.equals(dumper));
      Assertions.assertFalse(dumper.equals(dumper1));
      Assertions.assertFalse(dumper.equals(null));
      Assertions.assertFalse(dumper.equals(new ArrayList<>(1)));
      Assertions.assertTrue(dumper.hashCode() >= 0 || dumper.hashCode() <= 0);
      Assertions.assertTrue(dumper.hashCode() != dumper1.hashCode());

      Assertions.assertTrue(dumper.reference.equals(dumper.reference));
      Assertions.assertFalse(dumper.reference.equals(dumper1.reference));
      Assertions.assertFalse(dumper.reference.equals(null));
      Assertions.assertFalse(dumper.reference.equals(new ArrayList<>(1)));
      Assertions.assertTrue(dumper.reference.hashCode() >= 0 || dumper.reference.hashCode() <= 0);
      Assertions.assertTrue(dumper.reference.hashCode() != dumper1.reference.hashCode());
    }
  }

  @Test
  void setNativeLong() {
    Pointer ptr = new Pointer(Native.malloc(8));
    DefaultDumper.setNativeLong(ptr, 0, Integer.MAX_VALUE, 4);
    Assertions.assertEquals(Integer.MAX_VALUE, ptr.getInt(0));
    DefaultDumper.setNativeLong(ptr, 0, Long.MAX_VALUE, 8);
    Assertions.assertEquals(Long.MAX_VALUE, ptr.getLong(0));
    Native.free(Pointer.nativeValue(ptr));
  }
}
