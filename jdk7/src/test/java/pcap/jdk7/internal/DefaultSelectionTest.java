/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.Pcap;
import pcap.spi.Selection;
import pcap.spi.Selector;
import pcap.spi.Service;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
class DefaultSelectionTest {

  @Test
  void attach() {
    DefaultSelection selection = new DefaultSelection(null, null, null);
    Assertions.assertNotNull(selection.attach("Hello!"));
    Assertions.assertEquals("Hello!", selection.attachment());
  }

  @Test
  void attachment() {
    DefaultSelection selection = new DefaultSelection(null, null, null);
    Assertions.assertNotNull(selection.attach("Hello!"));
    Assertions.assertEquals("Hello!", selection.attachment());
    Assertions.assertNotNull(selection.attach(null));
    Assertions.assertNull(selection.attachment());
  }

  @Test
  void readyOperations() {
    DefaultSelection selection = new DefaultSelection(null, null, null);
    selection.setReadyOperation(Selection.OPERATION_READ);
    Assertions.assertEquals(selection.readyOperations(), Selection.OPERATION_READ);
    selection.setReadyOperation(Selection.OPERATION_READ | Selection.OPERATION_WRITE);
    Assertions.assertEquals(
        selection.readyOperations(), Selection.OPERATION_READ | Selection.OPERATION_WRITE);
  }

  @Test
  void isReadable() {
    DefaultSelection selection = new DefaultSelection(null, null, null);
    selection.setReadyOperation(Selection.OPERATION_READ);
    Assertions.assertTrue(selection.isReadable());
    selection.setReadyOperation(Selection.OPERATION_READ | Selection.OPERATION_WRITE);
    Assertions.assertTrue(selection.isReadable());
    selection.setReadyOperation(
        Selection.OPERATION_WRITE | Selection.OPERATION_READ | Selection.OPERATION_WRITE);
    Assertions.assertTrue(selection.isReadable());
    selection.setReadyOperation(Selection.OPERATION_WRITE);
    Assertions.assertFalse(selection.isReadable());
  }

  @Test
  void isWritable() {
    DefaultSelection selection = new DefaultSelection(null, null, null);
    selection.setReadyOperation(Selection.OPERATION_WRITE);
    Assertions.assertTrue(selection.isWritable());
    selection.setReadyOperation(Selection.OPERATION_READ | Selection.OPERATION_WRITE);
    Assertions.assertTrue(selection.isWritable());
    selection.setReadyOperation(
        Selection.OPERATION_WRITE | Selection.OPERATION_READ | Selection.OPERATION_WRITE);
    Assertions.assertTrue(selection.isWritable());
    selection.setReadyOperation(Selection.OPERATION_READ);
    Assertions.assertFalse(selection.isWritable());
  }

  @Test
  void interestOperations() throws Exception {
    Service service = Service.Creator.create("PcapService");
    final Pcap pcap = service.live(service.interfaces(), new DefaultLiveOptions());
    final Selector selector = service.selector();
    final Selection selection = pcap.register(selector, Selection.OPERATION_READ, null);
    selection.interestOperations(Selection.OPERATION_READ);
    Assertions.assertEquals(Selection.OPERATION_READ, selection.interestOperations());
    selection.interestOperations(Selection.OPERATION_WRITE);
    Assertions.assertEquals(Selection.OPERATION_WRITE, selection.interestOperations());
    selection.interestOperations(Selection.OPERATION_WRITE | Selection.OPERATION_READ);
    Assertions.assertEquals(
        Selection.OPERATION_WRITE | Selection.OPERATION_READ, selection.interestOperations());
    selection.cancel();
    selector.close();
    pcap.close();
  }

  @Test
  void selectorSelectableAndCancel() throws Exception {
    Service service = Service.Creator.create("PcapService");
    DefaultPcap pcap = (DefaultPcap) service.live(service.interfaces(), new DefaultLiveOptions());
    final AbstractSelector<?> selector = (AbstractSelector<?>) service.selector();
    final Selection selection = selector.register(pcap, Selection.OPERATION_READ, null);
    Assertions.assertNotNull(selection.selector());
    Assertions.assertNotNull(selection.selectable());
    selection.cancel();
    Assertions.assertTrue(selection.hashCode() != 0);
    pcap.close();
    selector.close();
  }

  @Test
  void equalsAndHasCode() throws Exception {
    Service service = Service.Creator.create("PcapService");
    final DefaultPcap pcap1 =
        (DefaultPcap) service.live(service.interfaces(), new DefaultLiveOptions());
    final DefaultPcap pcap2 =
        (DefaultPcap) service.live(service.interfaces(), new DefaultLiveOptions());
    Selection selection1 = new DefaultSelection(null, pcap1, null);
    Selection selection2 = new DefaultSelection(null, pcap2, null);
    Object NULL_REF = null;
    Integer OBJ = Integer.valueOf(0);
    Assertions.assertTrue(selection1.equals(selection1));
    Assertions.assertFalse(selection1.equals(selection2));
    Assertions.assertFalse(selection1.equals(NULL_REF));
    Assertions.assertFalse(selection1.equals(OBJ));
    Assertions.assertTrue(pcap1.hashCode() != pcap2.hashCode());
    pcap1.close();
    pcap2.close();
  }

  @Test
  void validateOperations() {
    DefaultSelection.validateOperations(Selection.OPERATION_READ);
    DefaultSelection.validateOperations(Selection.OPERATION_WRITE);
    DefaultSelection.validateOperations(Selection.OPERATION_READ | Selection.OPERATION_WRITE);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            DefaultSelection.validateOperations(
                Selection.OPERATION_READ | Selection.OPERATION_WRITE | 100);
          }
        });
  }
}
