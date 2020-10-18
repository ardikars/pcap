package pcap.spi.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import pcap.spi.PacketHandler;
import pcap.spi.PacketHeader;

/**
 * Indicate the {@link pcap.spi.Pcap#dispatch(int, PacketHandler, Object)} or {@link
 * pcap.spi.Pcap#next(PacketHeader)} are capable for perform non-blocking I/O. {@link pcap.spi.Pcap}
 * must be set in non-blocking mode by calling {@link pcap.spi.Pcap#setNonBlock(boolean)} ({@code
 * true}).
 *
 * @since 1.0.0
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Async {

  int timeout() default -1;
}
