/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import java.util.logging.Level;
import java.util.logging.Logger;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.Ip4;
import pcap.codec.ip.Ip6;
import pcap.codec.tcp.Tcp;
import pcap.codec.udp.Udp;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;
import pcap.spi.util.DefaultTimeout;

public class Application {

  private static final Logger LOGGER = Logger.getLogger(Application.class.getSimpleName());

  public static void main(String[] args)
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Service service = Service.Creator.create("PcapService");
    Interface devices = service.interfaces();
    for (Interface device : devices) {
      LOGGER.fine("[*] Device name   : " + device.name() + " (" + device.description() + ")");
    }
    Interface dev1 = devices;
    Interface dev2 = devices.next().next();
    LOGGER.fine("");
    System.out.println("[v] Chosen device : " + dev1.name() + " : " + dev2.name());
    Pcap live1 = service.live(dev1, new DefaultLiveOptions().immediate(false));
    Pcap live2 = service.live(dev2, new DefaultLiveOptions().immediate(false));
    PacketBuffer packetBuffer = live1.allocate(PacketBuffer.class);
    PacketHeader packetHeader = live1.allocate(PacketHeader.class);
    Timeout timeout = new DefaultTimeout(1000000L, Timeout.Precision.MICRO);
    Selector selector = service.selector();
    selector.register(live2);
    selector.register(live1);
    for (int i = 0; i < 10; i++) {
      try {
        Iterable<Selectable> select = selector.select(timeout);
        for (Selectable selectable : select) {
          Pcap pcap = (Pcap) selectable;
          pcap.nextEx(packetHeader, packetBuffer);
          Ethernet ethernet = packetBuffer.cast(Ethernet.class);
          System.out.println(ethernet);
          if (ethernet.type() == Ip4.TYPE) {
            Ip4 ip4 = packetBuffer.readerIndex(ethernet.size()).cast(Ip4.class);
            System.out.println(ip4);
            if (ip4.protocol() == Tcp.TYPE) {
              Tcp tcp = packetBuffer.readerIndex(ethernet.size() + ip4.size()).cast(Tcp.class);
              System.out.println(tcp);
            } else if (ip4.protocol() == Udp.TYPE) {
              Udp udp = packetBuffer.readerIndex(ethernet.size() + ip4.size()).cast(Udp.class);
              System.out.println(udp);
            }
          } else if (ethernet.type() == Ip6.TYPE) {
            Ip6 ip6 = packetBuffer.readerIndex(ethernet.size()).cast(Ip6.class);
            System.out.println(ip6);
            if (ip6.nextHeader() == Tcp.TYPE) {
              Tcp tcp = packetBuffer.readerIndex(ethernet.size() + ip6.size()).cast(Tcp.class);
              System.out.println(tcp);
            } else if (ip6.nextHeader() == Udp.TYPE) {
              Udp udp = packetBuffer.readerIndex(ethernet.size() + ip6.size()).cast(Udp.class);
              System.out.println(udp);
            }
          }
        }
      } catch (TimeoutException e) {
        LOGGER.log(Level.WARNING, e.getMessage());
      } catch (BreakException e) {
        LOGGER.log(Level.WARNING, e.getMessage());
      }
    }
  }
}
