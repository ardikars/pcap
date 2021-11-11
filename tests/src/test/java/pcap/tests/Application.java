/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import java.nio.charset.StandardCharsets;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.loopback.Loopback;
import pcap.codec.sll.Sll;
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
    final var selector = service.selector();
    System.out.println(service.version());
    while (interfaceIterator.hasNext()) {
      final var source = interfaceIterator.next();
      System.out.println(source.name());
      System.out.println(source.description());
      var pcap = service.live(source, new DefaultLiveOptions());
      System.out.println(source.description());
      pcap.register(
          selector,
          Selection.OPERATION_READ,
          pcap.allocate(PacketBuffer.class).capacity(pcap.snapshot()));
    }
    var timeout = new DefaultTimeout(1000000000L, Timeout.Precision.MICRO);
    var handler = new Handler();
    for (int i = 0; i < 1000; i++) {
      try {
        int nEvents =
            selector.select(
                new Consumer<Selection>() {
                  @Override
                  public void accept(Selection next) {
                    final var selectable = next.selectable();
                    final var p = (Pcap) selectable;
                    if (next.isReadable()) {
                      System.out.println("READABLE");
                      try {
                        p.dispatch(1, handler, (PacketBuffer) next.attachment());
                      } catch (BreakException e) {
                        e.printStackTrace();
                      } catch (ErrorException e) {
                        e.printStackTrace();
                      } catch (TimeoutException e) {
                        e.printStackTrace();
                      }
                      next.interestOperations(Selection.OPERATION_WRITE);
                    } else if (next.isWritable()) {
                      System.out.println("WRITEABLE");
                      var buf = (PacketBuffer) next.attachment();
                      if (p.datalink() == Loopback.TYPE) {
                        Loopback loopback = buf.cast(Loopback.class);
                        System.out.println(loopback);
                      } else if (p.datalink() == Sll.TYPE) {
                        Sll sll = buf.cast(Sll.class);
                        System.out.println(sll);
                      } else {
                        Ethernet ethernet = buf.cast(Ethernet.class);
                        System.out.println(ethernet);
                      }

                      if (p.datalink() != Loopback.TYPE && p.datalink() != Sll.TYPE) {
                        /*try {
                          p.sendPacket(buf);
                        } catch (ErrorException e) {
                          System.out.println(e.getMessage());
                        }*/
                      }
                      next.interestOperations(Selection.OPERATION_READ);
                    }
                  }
                },
                timeout);
      } catch (TimeoutException e) {
        System.err.println(e);
      }
    }
    selector.close();
  }

  private static final class Handler implements PacketHandler<PacketBuffer> {

    private static final PacketBuffer.Charset CHARSET = () -> StandardCharsets.US_ASCII.name();

    @Override
    public void gotPacket(PacketBuffer attachment, PacketHeader header, PacketBuffer buffer) {
      attachment.setIndex(0, 0);
      attachment.writeBytes(buffer); // copy packet to attachment
    }
  }
}
