/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.loopback.Loopback;
import pcap.codec.sll.Sll;
import pcap.spi.Interface;
import pcap.spi.Packet;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHandler;
import pcap.spi.PacketHeader;
import pcap.spi.Pcap;
import pcap.spi.Selection;
import pcap.spi.Service;
import pcap.spi.Timeout;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.option.DefaultLiveOptions;
import pcap.spi.util.Consumer;
import pcap.spi.util.DefaultTimeout;

public class Application {

  public static void main(String[] pargs) throws Exception {
    final var service = Service.Creator.create("PcapService");
    final var interfaces = service.interfaces();
    final var interfaceIterator = interfaces.iterator();
    try (final var selector = service.selector()) {
      System.out.printf("Version: %s%n", service.version());
      List<Pcap> pcaps = new LinkedList<Pcap>();
      while (interfaceIterator.hasNext()) {
        final var source = interfaceIterator.next();
        if ((source.flags() & Interface.PCAP_IF_UP) != 0) {
          System.out.printf("Interface name: %s%n", source.name());
          var pcap = service.live(source, new DefaultLiveOptions());
          pcaps.add(pcap);
        }
      }
      for (Pcap pcap : pcaps) {
        pcap.register(
            selector,
            Selection.OPERATION_READ,
            pcap.allocate(PacketBuffer.class).capacity(pcap.snapshot()));
      }
      var timeout = new DefaultTimeout(1000000000L, Timeout.Precision.MICRO);
      var handler = new Handler();
      var consumer = new Processor(handler);
      for (int i = 0; i < 100; i++) {
        try {
          int nEvents = selector.select(consumer, timeout);
          System.out.printf("Selected events: %d%n", nEvents);
        } catch (TimeoutException e) {
          System.err.println(e);
        }
      }
      for (Pcap pcap : pcaps) {
        pcap.close();
      }
    }
  }

  private static final class Processor implements Consumer<Selection> {

    private final Handler handler;

    private Processor(Handler handler) {
      this.handler = handler;
    }

    @Override
    public void accept(Selection next) {
      final var selectable = next.selectable();
      final var p = (Pcap) selectable;
      if (next.isReadable()) {
        System.out.println("### Got read event ###");
        try {
          p.dispatch(1, handler, (PacketBuffer) next.attachment());
        } catch (BreakException e) {
          System.err.println(e);
        } catch (ErrorException e) {
          System.err.println(e);
        } catch (TimeoutException e) {
          System.err.println(e);
        }
        next.interestOperations(Selection.OPERATION_WRITE);
      } else if (next.isWritable()) {
        System.out.println("### Got write event ###");
        var buf = (PacketBuffer) next.attachment();
        Packet packet;
        if (p.datalink() == Loopback.TYPE) {
          packet = buf.cast(Loopback.class);
        } else if (p.datalink() == Sll.TYPE) {
          packet = buf.cast(Sll.class);
        } else {
          packet = buf.cast(Ethernet.class);
        }
        System.out.println("*** DO WRITE IF POSSIBLE ***");

        if (p.datalink() != Loopback.TYPE && p.datalink() != Sll.TYPE) {
          try {
            System.out.println(packet);
            p.sendPacket(buf);
          } catch (ErrorException e) {
            System.out.println(e.getMessage());
          }
        }
        next.interestOperations(Selection.OPERATION_READ);
      }
    }
  }

  private static final class Handler implements PacketHandler<PacketBuffer> {

    private static final PacketBuffer.Charset CHARSET = () -> StandardCharsets.US_ASCII.name();

    @Override
    public void gotPacket(PacketBuffer attachment, PacketHeader header, PacketBuffer buffer) {
      System.out.println("*** DO READ ***");
      attachment.setIndex(0, 0);
      attachment.writeBytes(buffer); // copy packet to attachment
    }
  }
}
