package pcap.tests;

import org.openjdk.jmh.annotations.*;
import pcap.common.memory.Memory;
import pcap.common.memory.MemoryAllocator;

public class ByteBufBenchmark {

  private static final int FORK_VALUE = 1;
  private static final int FORK_WARMUPDS = 1;
  private static final int WARMUP_ITERATIONS = 2;

  // Set

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setByte(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setByte(i, i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setShort(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setShort(i, i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setShortLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setShortLE(i, i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setInt(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setInt(i, i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setIntLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setIntLE(i, i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setFloat(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setFloat(i, i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setFloatLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setFloatLE(i, i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setLong(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setLong(i, i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setLongLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setLongLE(i, i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setDouble(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setDouble(i, i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void setDoubleLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.setDoubleLE(i, i);
    }
  }

  // Write

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeByte(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeByte(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeShort(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeShort(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeShortLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeShortLE(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeInt(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeInt(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeIntLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeIntLE(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeFloat(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeFloat(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeFloatLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeFloatLE(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeLong(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeLong(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeLongLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeLongLE(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeDouble(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeDouble(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void writeDoubleLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.writeDoubleLE(i);
    }
  }

  // get

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getByte(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getByte(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getShort(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getShort(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getShortLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getShortLE(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getInt(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getInt(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getIntLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getIntLE(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getFloat(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getFloat(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getFloatLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getFloatLE(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getLong(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getLong(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getLongLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getLongLE(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getDouble(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getDouble(i);
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void getDoubleLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.getDoubleLE(i);
    }
  }

  // Read

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readByte(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readByte();
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readShort(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readShort();
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readShortLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readShortLE();
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readInt(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readInt();
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readIntLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readIntLE();
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readFloat(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readFloat();
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readFloatLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readFloatLE();
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readLong(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readLong();
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readLongLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readLongLE();
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readDouble(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readDouble();
    }
  }

  @Fork(value = FORK_VALUE, warmups = FORK_WARMUPDS)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @Warmup(iterations = WARMUP_ITERATIONS)
  public void readDoubleLE(ExecutionPlan plan) {
    for (int i = 0; i < plan.iterations; i++) {
      plan.memory.readDoubleLE();
    }
  }

  @State(Scope.Benchmark)
  public static class ExecutionPlan {

    @Param({"2", "3"})
    public int iterations;

    public Memory memory;

    @Setup(Level.Invocation)
    public void setUp() {
      memory = MemoryAllocator.create("NioDirectMemoryAllocator").allocate(iterations);
    }
  }
}
