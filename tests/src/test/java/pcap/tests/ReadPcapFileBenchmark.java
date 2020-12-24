/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.option.DefaultOfflineOptions;

/*
# uname -a
Linux pcap 5.4.0-56-generic #62-Ubuntu SMP Mon Nov 23 19:20:19 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

# free -m
              total        used        free      shared  buff/cache   available
Mem:           7831        4386        1969         310        1476        2861
Swap:          2047        1712         335

# lscpu | grep  'CPU(s):'
CPU(s):                          8
NUMA node0 CPU(s):               0-7


Benchmark                     (iterations)   Mode  Cnt     Score      Error  Units
ReadPcapFileBenchmark.loop             100  thrpt    3   355.821 ± 2941.121  ops/s
ReadPcapFileBenchmark.loop             200  thrpt    3   443.680 ± 1836.874  ops/s
ReadPcapFileBenchmark.nextEx           100  thrpt    3  2400.190 ±  320.529  ops/s
ReadPcapFileBenchmark.nextEx           200  thrpt    3  2082.465 ±  322.096  ops/s
 */
public class ReadPcapFileBenchmark {

  public static void main(String[] args) throws RunnerException {
    Options opt =
        new OptionsBuilder().include(ReadPcapFileBenchmark.class.getSimpleName()).forks(1).build();
    new Runner(opt).run();
  }

  @Warmup(iterations = 2)
  @Measurement(iterations = 3)
  @BenchmarkMode(Mode.Throughput)
  @Benchmark
  public void nextEx(ExecutionPlan plan) {
    while (true) {
      try {
        plan.pcap.nextEx(plan.header, plan.buffer);
        assert plan.header.captureLength() > 0;
        assert plan.header.length() > 0;
        assert plan.buffer.capacity() > 0;
      } catch (BreakException e) {
        break;
      } catch (TimeoutException e) {
        throw new AssertionError();
      } catch (ErrorException e) {
        throw new AssertionError();
      }
    }
    plan.pcap.close();
  }

  @Warmup(iterations = 2)
  @BenchmarkMode(Mode.Throughput)
  @Measurement(iterations = 3)
  @Benchmark
  public void loop(ExecutionPlan plan) {
    try {
      plan.pcap.loop(-1, plan.handler, null);
    } catch (BreakException e) {
      throw new AssertionError();
    } catch (ErrorException e) {
      throw new AssertionError();
    }
    plan.pcap.close();
  }

  @State(Scope.Benchmark)
  public static class ExecutionPlan {

    @Param({"100", "200"})
    public int iterations;

    public Pcap pcap;
    public PacketHeader header;
    public PacketBuffer buffer;
    public PacketHandler<Object> handler;

    @Setup(Level.Invocation)
    public void setUp() {
      try {
        Service service = Service.Creator.create("PcapService");
        pcap = service.offline("tests/src/test/resources/ping.pcap", new DefaultOfflineOptions());
        header = pcap.allocate(PacketHeader.class);
        buffer = pcap.allocate(PacketBuffer.class);
        handler =
            new PacketHandler<Object>() {
              @Override
              public void gotPacket(Object args, PacketHeader header, PacketBuffer buffer) {
                assert header.captureLength() > 0;
                assert header.length() > 0;
                assert buffer.capacity() > 0;
              }
            };
      } catch (ErrorException e) {
        throw new AssertionError();
      }
    }
  }
}
