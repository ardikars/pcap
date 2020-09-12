package pcap.codec;

import java.lang.annotation.*;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicReference;
import pcap.common.memory.Memory;

public interface PacketPipeline extends Iterable<PacketPipeline.PacketHandler> {

  class Creator {

    public static PacketPipeline create() {
      return new DefaultPacketPipeline();
    }
  }

  PacketPipeline addFirst(PacketHandler handler);

  PacketPipeline addLast(PacketHandler handler);

  void start(DataLinkLayer type, Memory buffer);

  abstract class AbstractPacketHandler<T extends Packet> implements PacketHandler<T> {

    @Override
    public void doHandle(T packet) {
      final List<T> packets = packet.get(type());
      if (packets != null && !packets.isEmpty()) {
        for (int i = 0; i < packets.size(); i++) {
          handle(packets.get(i));
        }
      }
    }
  }

  interface PacketHandler<T extends Packet> {

    void handle(T packet);

    void doHandle(T packet);

    Class<T> type();

    @Inherited
    @Documented
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    @interface Sharable {}
  }

  final class DefaultPacketPipeline implements PacketPipeline {

    private PacketHandlerContext head;
    private PacketHandlerContext tail;

    @Override
    public DefaultPacketPipeline addFirst(PacketHandler handler) {
      ensureAddable(handler);
      final PacketHandlerContext nextCtx = head;
      final PacketHandlerContext newCtx = new PacketHandlerContext(null, handler, nextCtx);
      head = newCtx;
      if (nextCtx == null) {
        tail = newCtx;
      } else {
        nextCtx.prev = newCtx;
      }
      return this;
    }

    @Override
    public DefaultPacketPipeline addLast(PacketHandler handler) {
      ensureAddable(handler);
      final PacketHandlerContext prevCtx = tail;
      final PacketHandlerContext newCtx = new PacketHandlerContext(prevCtx, handler, null);
      tail = newCtx;
      if (prevCtx == null) {
        head = newCtx;
      } else {
        prevCtx.next = newCtx;
      }
      return this;
    }

    @Override
    public void start(DataLinkLayer type, Memory buffer) {
      Packet packet = type.newInstance(buffer);
      final Iterator<PacketHandler> iterator = iterator();
      for (; ; ) {
        if (!iterator.hasNext()) {
          break;
        }
        final PacketHandler handler = iterator.next();
        handler.doHandle(packet);
      }
    }

    private PacketHandlerContext headContext(Class<? extends PacketHandler> type) {
      PacketHandlerContext ctx = head;
      for (; ; ) {
        if (ctx == null) {
          return ctx;
        }
        if (ctx.handler.getClass() == type) {
          return ctx;
        } else {
          ctx = ctx.next;
        }
      }
    }

    private void ensureAddable(PacketHandler handler) {
      if (headContext(handler.getClass()) != null) {
        if (handler.getClass().getAnnotation(PacketHandler.Sharable.class) == null) {
          throw new UnsupportedOperationException(
              String.format(
                  "%s is not a @Sharable handler, so can't be added or removed multiple times.",
                  handler.getClass().getName()));
        }
      }
    }

    @Override
    public Iterator<PacketHandler> iterator() {
      final AtomicReference<PacketHandlerContext> ctx = new AtomicReference<>(head);
      return new PacketHandlerIterator(ctx);
    }

    private static class PacketHandlerIterator implements Iterator<PacketHandler> {

      private final AtomicReference<PacketHandlerContext> ctx;

      private PacketHandlerIterator(AtomicReference<PacketHandlerContext> ctx) {
        this.ctx = ctx;
      }

      @Override
      public boolean hasNext() {
        return ctx.get() != null;
      }

      @Override
      public PacketHandler next() {
        if (!hasNext()) {
          throw new NoSuchElementException("No more packet handler.");
        }
        PacketHandlerContext current = ctx.get();
        ctx.set(ctx.get().next);
        return current.handler;
      }
    }

    private static final class PacketHandlerContext {

      private final PacketHandler handler;
      private PacketHandlerContext prev;
      private PacketHandlerContext next;

      private PacketHandlerContext(
          PacketHandlerContext prev, PacketHandler handler, PacketHandlerContext next) {
        this.handler = handler;
        this.prev = prev;
        this.next = next;
      }
    }
  }
}
