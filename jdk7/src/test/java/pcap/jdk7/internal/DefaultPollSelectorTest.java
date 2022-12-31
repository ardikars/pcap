/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Platform;
import java.util.Iterator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import pcap.spi.Pcap;
import pcap.spi.Selectable;
import pcap.spi.Selection;
import pcap.spi.Selector;
import pcap.spi.Service;
import pcap.spi.Timeout;
import pcap.spi.exception.TimeoutException;
import pcap.spi.option.DefaultLiveOptions;
import pcap.spi.util.Consumer;
import pcap.spi.util.DefaultTimeout;

class DefaultPollSelectorTest extends AbstractSelectorTest {

  boolean isUnix() {
    return !Platform.isWindows() && !Platform.isWindowsCE();
  }

  @Test
  void toJavaEvent() {
    int iops = Selection.OPERATION_READ | Selection.OPERATION_WRITE;
    Assertions.assertEquals(
        Selection.OPERATION_READ,
        DefaultPollSelector.toJavaEvent(DefaultPollSelector.POLLIN, iops));
    Assertions.assertEquals(
        Selection.OPERATION_WRITE,
        DefaultPollSelector.toJavaEvent(DefaultPollSelector.POLLOUT, iops));
  }

  @Test
  void toPollEvent() {
    Assertions.assertEquals(
        DefaultPollSelector.POLLIN, DefaultPollSelector.toPollEvent(Selection.OPERATION_READ));
    Assertions.assertEquals(
        DefaultPollSelector.POLLOUT, DefaultPollSelector.toPollEvent(Selection.OPERATION_WRITE));
    Assertions.assertEquals(
        DefaultPollSelector.POLLIN | DefaultPollSelector.POLLOUT,
        DefaultPollSelector.toPollEvent(Selection.OPERATION_READ | Selection.OPERATION_WRITE));
  }

  @Test
  void pollfdTest() {
    DefaultPollSelector.pollfd pollfd1 = new DefaultPollSelector.pollfd();
    DefaultPollSelector.pollfd pollfd2 = new DefaultPollSelector.pollfd();
    Object nullRef = null;
    Assertions.assertEquals(pollfd1, pollfd2);
    pollfd1.equals(pollfd1);
    Assertions.assertNotEquals(pollfd1, nullRef);
    pollfd1.fd = 1;
    Assertions.assertNotEquals(pollfd1, pollfd2);
    Assertions.assertTrue(pollfd1.hashCode() >= 0 || pollfd1.hashCode() <= 0);
  }

  @Test
  void doWhile() throws Exception {
    if (!isUnix()) {
      Assertions.assertFalse(isUnix());
      return;
    }
    final Service service = Service.Creator.create("PcapService");
    final Selector selector = service.selector();
    DefaultPollSelector pollSelector = (DefaultPollSelector) selector;
    Assertions.assertFalse(pollSelector.doWhile(0, DefaultPollSelector.EINTR));
    Assertions.assertFalse(pollSelector.doWhile(-1, DefaultPollSelector.EINTR + 1));
    Assertions.assertTrue(pollSelector.doWhile(-1, DefaultPollSelector.EINTR));
    selector.close();
  }

  @Test
  void toIterable() throws Exception {
    if (!isUnix()) {
      Assertions.assertFalse(isUnix());
      return;
    }
    final Service service = Service.Creator.create("PcapService");
    final Selector selector = service.selector();
    final DefaultPollSelector pollSelector = (DefaultPollSelector) selector;
    Iterable<Selectable> selected1 = pollSelector.toIterableSelectable(-1, 0);
    Iterator<Selectable> iterator1 = selected1.iterator();
    Assertions.assertFalse(iterator1.hasNext());
    Iterable<Selectable> selected2 = pollSelector.toIterableSelectable(10, 0);
    Iterator<Selectable> iterator2 = selected2.iterator();
    Assertions.assertFalse(iterator2.hasNext());
    Pcap pcap = service.live(service.interfaces(), new DefaultLiveOptions());
    pollSelector.register(pcap);

    Assertions.assertThrows(
        TimeoutException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            try (Pcap live = service.live(service.interfaces(), new DefaultLiveOptions())) {
              pollSelector.register(live);
              pollSelector.toIterableSelectable(0, 0);
            }
          }
        });
    selector.close();
    pcap.close();
  }

  @Test
  void selectConsumer() throws Exception {
    if (!isUnix()) {
      Assertions.assertFalse(isUnix());
      return;
    }
    final Service service = Service.Creator.create("PcapService");
    final Selector selector = service.selector();
    final DefaultPollSelector pollSelector = (DefaultPollSelector) selector;
    DefaultPcap pcap = (DefaultPcap) service.live(service.interfaces(), new DefaultLiveOptions());
    final Selection register = pcap.register(pollSelector, Selection.OPERATION_READ, null);

    final Timeout timeout = new DefaultTimeout(1000000L, Timeout.Precision.MICRO);
    final Consumer<Selection> consumer =
        new Consumer<Selection>() {
          @Override
          public void accept(Selection selection) {}
        };
    Assertions.assertThrows(
        TimeoutException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            pollSelector.consume(0, timeout, consumer);
          }
        });
    Assertions.assertEquals(-1, pollSelector.consume(-1, timeout, consumer));
    pollSelector.consume(1, timeout, consumer);
    pollSelector.cancel(pcap);
    selector.close();
    pcap.close();
  }
}
