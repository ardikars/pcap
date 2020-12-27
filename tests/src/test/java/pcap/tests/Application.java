/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.Ip4;
import pcap.codec.ip.Ip6;
import pcap.codec.tcp.Tcp;
import pcap.codec.udp.Udp;
import pcap.spi.*;
import pcap.spi.annotation.Async;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

import java.util.logging.Level;
import java.util.logging.Logger;

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
    LOGGER.fine("");
    LOGGER.fine("[v] Chosen device : " + devices.name());
    try (Pcap live = service.live(devices, new DefaultLiveOptions())) {
      PacketBuffer packetBuffer = live.allocate(PacketBuffer.class);
      PacketHeader packetHeader = live.allocate(PacketHeader.class);
      for (int i = 0; i < 10; i++) {
        try {
          live.nextEx(packetHeader, packetBuffer);
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
        } catch (TimeoutException e) {
          LOGGER.log(Level.WARNING, e.getMessage());
        } catch (BreakException e) {
          LOGGER.log(Level.WARNING, e.getMessage());
        }
      }
      LOGGER.fine(live.stats().toString());
    } catch (ErrorException e) {
      LOGGER.log(Level.WARNING, e.getMessage());
    }
  }
}
