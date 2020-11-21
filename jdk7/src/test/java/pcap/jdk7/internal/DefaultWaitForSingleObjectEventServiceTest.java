/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Platform;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.*;
import pcap.spi.annotation.Async;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
public class DefaultWaitForSingleObjectEventServiceTest extends BaseTest {

  private Service service;
  private DefaultWaitForSingleObjectEventService eventService;

  @BeforeEach
  void setUp() throws ErrorException {
    this.service = Service.Creator.create("PcapService");
    this.eventService = new DefaultWaitForSingleObjectEventService();
  }

  @Test
  void open()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    if (Platform.isWindows()) {
      Interface lo = loopbackInterface(service);
      try (Pcap live = service.live(lo, new DefaultLiveOptions())) {
        live.setNonBlock(true);
        if (Platform.isWindows()) {
          DefaultPollEventServiceTest.MyProxy myProxy =
              eventService.open(live, DefaultPollEventServiceTest.MyProxy.class);
          Assertions.assertNotNull(myProxy);

          try {
            myProxy.dispatch(
                1,
                new PacketHandler<String>() {
                  @Override
                  public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {
                    // ok
                  }
                },
                "");
          } catch (BreakException e) {
            //
          }
          PacketHeader header = myProxy.allocate(PacketHeader.class);
          PacketBuffer buffer = myProxy.allocate(PacketBuffer.class);
          try {
            myProxy.nextEx(header, buffer);
          } catch (BreakException e) {
            //
          } catch (TimeoutException e) {
            //
          } catch (ErrorException e) {

          }
          buffer = myProxy.next(header);
        }
      }
    }
  }

  @Test
  void register() {
    try {
      DefaultWaitForSingleObjectEventService.register(false);
    } catch (UnsatisfiedLinkError e) {
    }
    try {
      DefaultWaitForSingleObjectEventService.register(true);
    } catch (UnsatisfiedLinkError e) {
    }
  }

  interface MyProxy extends Pcap {

    @Async(timeout = 1000) // wait for 1 secs
    @Override
    void nextEx(PacketHeader packetHeader, PacketBuffer packetBuffer)
        throws BreakException, ErrorException, TimeoutException;

    @Async(timeout = 0) // no wait
    @Override
    PacketBuffer next(PacketHeader header);

    @Async(timeout = -1) // wait till ready to perform i/o operation
    @Override
    <T> void dispatch(int count, PacketHandler<T> handler, T args)
        throws BreakException, ErrorException;
  }
}
