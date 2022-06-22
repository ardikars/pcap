/*
 * Copyright (c) 2020-2021 Pcap Project
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

class DefaultWaitForMultipleObjectsTest extends AbstractSelectorTest {

  boolean isWindows() {
    return Platform.isWindows() || Platform.isWindowsCE();
  }

  @Test
  void notRegistered() throws Exception {
    if (!isWindows()) {
      Assertions.assertFalse(isWindows());
      return;
    }
    Service service = Service.Creator.create("PcapService");
    Selector selector = service.selector();
    final DefaultWaitForMultipleObjectsSelector objectsSelector =
        (DefaultWaitForMultipleObjectsSelector) selector;
    Iterable<Selectable> selected1 = objectsSelector.toIterableSelectable(-1, 0);
    Iterator<Selectable> iterator1 = selected1.iterator();
    Assertions.assertFalse(iterator1.hasNext());

    Assertions.assertThrows(
        TimeoutException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            objectsSelector.toIterableSelectable(0x00000102, 0);
          }
        });
    selector.close();
  }

  @Test
  void select() throws Exception {
    if (!isWindows()) {
      Assertions.assertFalse(isWindows());
      return;
    }
    final Service service = Service.Creator.create("PcapService");
    final Selector selector = service.selector();
    final DefaultWaitForMultipleObjectsSelector objectsSelector =
        (DefaultWaitForMultipleObjectsSelector) selector;
    final DefaultTimeout timeout = new DefaultTimeout(1000000L, Timeout.Precision.MICRO);
    final Pcap live = service.live(service.interfaces(), new DefaultLiveOptions());
    final Selection selection = live.register(selector, Selection.OPERATION_READ, null);
    Assertions.assertNotNull(selection);

    final Consumer<Selection> consumer =
        new Consumer<Selection>() {
          @Override
          public void accept(Selection selection) {
            //
          }
        };

    try {
      selector.select(timeout);
    } catch (Exception e) {
      //
    }
    try {
      selector.select(consumer, timeout);
    } catch (Exception e) {
      //
    }

    Assertions.assertEquals(0, objectsSelector.callback(-1, timeout, consumer));
    Assertions.assertThrows(
        TimeoutException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            objectsSelector.callback(0x00000102, timeout, consumer);
          }
        });
    selector.close();
  }
}
