/** This code is licenced under the GPL version 2. */
package pcap.codec.ip;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.BaseTest;
import pcap.codec.TransportLayer;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.ip6.Authentication;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.PooledDirectByteBuffer;
import pcap.common.util.Hexs;

/** @author <a href="mailto:contact@ardikars.com">Langkuy</a> */
@RunWith(JUnitPlatform.class)
public class Ip6AuthenticationTest extends BaseTest {

  private final byte[] data = Hexs.parseHex(IPV6_AUTHENTICATION);

  private final Memory buf = allocator.allocate(data.length);

  @Override
  public void before() {
    buf.writeBytes(data);
    ethernet = Ethernet.newPacket(buf);
    final Authentication first = ethernet.getFirst(Authentication.class);
    Memory memory = first.buffer();
    Assertions.assertEquals(0, memory.readerIndex());
    Assertions.assertEquals(first.header().length(), memory.writerIndex());
  }

  private Authentication build() {
    Authentication.Builder builder = new Authentication.Builder();
    return builder
        .nextHeader(TransportLayer.valueOf((byte) 89))
        .payloadLength(0x04)
        .securityParameterIndex(256)
        .sequenceNumber(19)
        .integrityCheckValue(new byte[] {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
        .build();
  }

  @Test
  public void buildTest() {
    final Authentication authentication = build();
    final Memory buffer = authentication.buffer();

    Assertions.assertEquals(0, buffer.readerIndex());
    Assertions.assertEquals(authentication.header().length(), buffer.writerIndex());
    Assertions.assertTrue(buffer instanceof PooledDirectByteBuffer);

    final Authentication fromBuffer = Authentication.newPacket(buffer);
    Authentication.Header header = authentication.header();
    Authentication.Header headerFromBuffer = fromBuffer.header();
    Assertions.assertEquals(header, headerFromBuffer);

    buffer.release(); // don't forget to release the buffer to the pool
    final Memory noCopyBuffer =
        headerFromBuffer
            .buffer(); // this buffer is unuseabale because it's already released to the pool.
    Assertions.assertEquals(buffer.capacity(), noCopyBuffer.capacity());
    Assertions.assertEquals(buffer.maxCapacity(), noCopyBuffer.maxCapacity());
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            noCopyBuffer.release();
          }
        });
  }

  @Test
  public void mutateBuffer() {
    final Authentication pkt = build();
    final Memory buffer = pkt.buffer();

    final Authentication mutate =
        Authentication.newPacket(buffer)
            .builder()
            .nextHeader(TransportLayer.TCP)
            .payloadLength(0x04)
            .securityParameterIndex(200)
            .sequenceNumber(20)
            .integrityCheckValue(new byte[] {2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1})
            .reset()
            .build();

    buffer.readerIndex(0);
    Authentication mutated = Authentication.newPacket(buffer);

    Assertions.assertEquals(mutate.header(), mutated.header());
    Assertions.assertEquals(mutate.header().hashCode(), mutated.header().hashCode());

    Assertions.assertEquals(((PooledDirectByteBuffer) buffer).refCnt(), 1);
    Assertions.assertTrue(buffer.release()); // release buffer to the pool
    Assertions.assertEquals(mutate.buffer().capacity(), mutated.buffer().capacity());
    Assertions.assertEquals(mutate.buffer().maxCapacity(), mutated.buffer().maxCapacity());
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            mutate.buffer().release();
          }
        });
  }

  @Test
  public void toStringTest() {
    Authentication pkt = build();
    Assertions.assertNotNull(pkt.toString());
  }

  @AfterEach
  public void after() {
    try {
      buf.release();
    } catch (Throwable e) {
      //
    }
  }
}
