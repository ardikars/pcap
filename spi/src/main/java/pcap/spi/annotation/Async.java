/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import pcap.spi.PacketHandler;
import pcap.spi.PacketHeader;

/**
 * Indicate the {@link pcap.spi.Pcap#dispatch(int, PacketHandler, Object)} or {@link
 * pcap.spi.Pcap#next(PacketHeader)} is capable to perform non-blocking I/O. The device must be put
 * in non-blocking mode with a call to {@link pcap.spi.Pcap#setNonBlock(boolean)} ({@code true}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Async {

  int timeout() default -1;
}
