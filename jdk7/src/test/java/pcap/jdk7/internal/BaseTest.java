/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import java.util.Iterator;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.option.DefaultLiveOptions;

abstract class BaseTest {

  protected static final int MAX_PKT = 1;
  protected static final String SAMPLE_NANOSECOND_PCAP =
      "src/test/resources/sample_nanosecond.pcap";
  protected static final String SAMPLE_MICROSECOND_PCAP =
      "src/test/resources/sample_microsecond.pcap";
  protected static final int SAMPLE_PCAP_SNAPLEN = 262144;
  protected static final String SAMPLE_PCAPNG = "src/test/resources/sample.pcapng";

  private static Interface LOOPBACK;
  private static Interface ETHERNET;

  protected Interface loopbackInterface(Service service) throws ErrorException {
    if (LOOPBACK == null) {
      Iterator<Interface> iterator = service.interfaces().iterator();
      while (iterator.hasNext()) {
        Interface source = iterator.next();
        if ((source.flags() & 0x00000001) != 0) {
          LOOPBACK = source;
          return LOOPBACK;
        }
      }
      // try get by description
      iterator = service.interfaces().iterator();
      while (iterator.hasNext()) {
        Interface source = iterator.next();
        if (source.description() != null
            && source.description().toLowerCase().contains("loopback")) {
          LOOPBACK = source;
          return LOOPBACK;
        }
      }
      throw new ErrorException("Loopback interface is not found.");
    } else {
      return LOOPBACK;
    }
  }

  protected Interface ethernetInterface(Service service) throws ErrorException {
    if (ETHERNET == null) {
      for (Interface source : service.interfaces()) {
        try (final Pcap live = service.live(source, new DefaultLiveOptions())) {
          if (live.datalink() == 1) {
            ETHERNET = source;
          return ETHERNET;
          }
        } catch (Exception e) {
          // continue
        }
      }
      throw new ErrorException("Ethernet interface is not found.");
    } else {
      return ETHERNET;
    }
  }
}
