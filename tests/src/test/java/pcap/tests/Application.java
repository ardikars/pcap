/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import java.util.Iterator;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;
import pcap.spi.util.DefaultTimeout;

public class Application {

  public static void main(String[] pargs)
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    var service = Service.Creator.create("PcapService");
    Interface dev1 = service.interfaces();
    Interface dev2 = dev1.next();
    var pcap1 = service.live(dev1, new DefaultLiveOptions());
    var pcap2 = service.live(dev2, new DefaultLiveOptions());
    PacketHandler<Pcap> handler =
        (args, header, buffer) -> {
          System.out.println("Args     : " + args);
          System.out.println("Header   : " + header);
          System.out.println("Packet   : " + buffer);
        };
    pcap1.setNonBlock(true);
    pcap2.setNonBlock(true);
    Selector selector = service.selector();
    selector.register(pcap1);
    selector.register(pcap2);
    Timeout timeout = new DefaultTimeout(1000000L, Timeout.Precision.MICRO);
    try {
      Iterable<Selectable> selectables = selector.select(timeout);
      Iterator<Selectable> iterator = selectables.iterator();
      while (iterator.hasNext()) {
        Selectable next = iterator.next();
        Pcap pcap = (Pcap) next;
        pcap.dispatch(1, handler, pcap);
      }
    } catch (TimeoutException e) {
      System.err.println(e);
    } catch (BreakException e) {
      System.err.println(e);
    }
    pcap1.close();
    pcap2.close();
  }
}
