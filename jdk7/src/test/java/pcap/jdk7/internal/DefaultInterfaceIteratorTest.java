/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.util.Iterator;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import pcap.spi.Interface;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;

class DefaultInterfaceIteratorTest {

  private Service service;

  @BeforeEach
  void setUp() throws ErrorException {
    service = Service.Creator.create("PcapService");
  }

  @Test
  void iterate() throws ErrorException {
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    DefaultService defaultService = (DefaultService) service;
    NativeMappings.pcap_if pcapIf;
    PointerByReference alldevsPP = new PointerByReference();
    defaultService.checkFindAllDevs(NativeMappings.pcap_findalldevs(alldevsPP, errbuf));
    Pointer alldevsp = alldevsPP.getValue();
    pcapIf = new NativeMappings.pcap_if(alldevsp);
    NativeMappings.pcap_freealldevs(pcapIf.getPointer());

    final Iterator<Interface> iterator = pcapIf.iterator();
    while (iterator.hasNext()) {
      Assertions.assertNotNull(iterator.next());
      Assertions.assertThrows(
          UnsupportedOperationException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              iterator.remove();
            }
          });
    }
    Assertions.assertThrows(
        NoSuchElementException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            iterator.next();
          }
        });
  }
}
