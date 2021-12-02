/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import java.util.Iterator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import pcap.spi.Interface;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHandler;
import pcap.spi.PacketHeader;
import pcap.spi.Pcap;
import pcap.spi.Selectable;
import pcap.spi.Selection;
import pcap.spi.Selector;
import pcap.spi.Service;
import pcap.spi.Timeout;
import pcap.spi.exception.NoSuchSelectableException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.option.DefaultLiveOptions;
import pcap.spi.option.DefaultOfflineOptions;
import pcap.spi.util.DefaultTimeout;

abstract class AbstractSelectorTest extends BaseTest {

  @Test
  void registerTest() throws Exception {
    final Service service = Service.Creator.create("PcapService");
    Interface interfaces = service.interfaces();
    Interface dev1 = interfaces;
    Interface dev2 = loopbackInterface(service);
    Pcap live1 = service.live(dev1, new DefaultLiveOptions());
    Pcap live2 = service.live(dev2, new DefaultLiveOptions());
    final Timeout timeout = new DefaultTimeout(1000000L * 10, Timeout.Precision.MICRO);
    final Selector selector = service.selector();
    try {
      Assertions.assertThrows(
          NoSuchSelectableException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              selector.select(timeout);
            }
          });
      selector.register(live1);
      selector.register(live2);
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              selector.register(
                  new Selectable() {
                    @Override
                    public Object id() {
                      return null;
                    }

                    @Override
                    public void close() {
                      //
                    }

                    @Override
                    public Selection register(
                        Selector selector, int interestOperations, Object attachment)
                        throws IllegalArgumentException, IllegalStateException {
                      return null;
                    }
                  }); // invalid
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              selector.register(
                  service.offline(
                      "src/test/resources/sample_microsecond.pcap",
                      new DefaultOfflineOptions())); // invalid
            }
          });
      Iterable<Selectable> selected = selector.select(timeout);
      Iterator<Selectable> iterator = selected.iterator();
      PacketHandler<String> handler =
          new PacketHandler<String>() {
            @Override
            public void gotPacket(String args, PacketHeader header, PacketBuffer buffer) {}
          };
      while (iterator.hasNext()) {
        Selectable next = iterator.next();
        Pcap pcap = (Pcap) next;
        pcap.dispatch(1, handler, null);
      }
    } catch (TimeoutException e) {
      //
    }
    live1.close();
    live2.close();
    selector.close();
  }

  @Test
  void doubleRegisterTest() throws Exception {
    Service service = Service.Creator.create("PcapService");
    Interface interfaces = service.interfaces();
    final Pcap live1 = service.live(interfaces, new DefaultLiveOptions());
    final Pcap live2 = service.live(interfaces.next(), new DefaultLiveOptions());
    final Selector selector = service.selector();
    selector.register(live1);
    selector.register(live2);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            selector.register(live1);
          }
        });
    live1.close();
    live2.close();
    selector.close();
  }

  @Test
  void badArgsTest() throws Exception {
    Service service = Service.Creator.create("PcapService");
    final Selector selector = service.selector();
    Assertions.assertThrows(
        NoSuchSelectableException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            selector.select(new DefaultTimeout(1000, Timeout.Precision.MICRO));
          }
        });
    Pcap pcap = service.live(service.interfaces(), new DefaultLiveOptions());
    selector.register(pcap);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            selector.select(null);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            selector.select(new DefaultTimeout(1, Timeout.Precision.MICRO));
          }
        });
    selector.close();
  }

  @Test
  void autoClose() throws Exception {
    Service service = Service.Creator.create("PcapService");
    try (Selector selector = service.selector()) {
      Assertions.assertNotNull(selector);
    }
    Selector selector1 = service.selector();
    selector1.close();
    Selector selector2 = service.selector();
    selector2.register(service.live(service.interfaces(), new DefaultLiveOptions()));
    selector2.close();
  }

  @Test
  void accessClosedSelector() throws Exception {
    Service service = Service.Creator.create("PcapService");
    final Selector selector = service.selector();
    selector.close();
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            selector.register(null);
          }
        });
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            selector.select(null);
          }
        });
  }

  @Test
  void checkOpenState() throws Exception {
    final Service service = Service.Creator.create("PcapService");
    final AbstractSelector selector = (AbstractSelector) service.selector();
    selector.checkOpenState();
    selector.close();
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            selector.checkOpenState();
          }
        });
  }
}
