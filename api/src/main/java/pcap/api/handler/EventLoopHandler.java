/** This code is licenced under the GPL version 2. */
package pcap.api.handler;

import pcap.common.annotation.Inclubating;
import pcap.spi.PacketHandler;

/**
 * Every packet handler that extend this {@link EventLoopHandler} will be processed by event loop.
 *
 * @param <T> args type.
 */
@Inclubating
public interface EventLoopHandler<T> extends PacketHandler<T> {}
