/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.tests;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/*
# uname -a
Linux fedora 5.14.17-301.fc35.x86_64 #1 SMP Mon Nov 8 13:57:43 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

# free -m
               total        used        free      shared  buff/cache   available
Mem:            7809        5724         190         535        1894        1262
Swap:           7808        1825        5983

# lscpu | grep  'CPU(s):'
CPU(s):                          8
NUMA node0 CPU(s):               0-7

Benchmark                                      Mode  Cnt         Score           Error  Units
ReflectionUnReflectionBenchmark.reflection    thrpt    3  71488461.599 ± 165824639.685  ops/s
ReflectionUnReflectionBenchmark.unReflection  thrpt    3  83745795.935 ±  12614478.659  ops/s
 */
public class ReflectionUnReflectionBenchmark {

  static Constructor<MyClass> CONSTRUCTION_REFLECTION;
  static MethodHandle CONSTRUCTION_UNREFLECTION;

  static {
    try {
      CONSTRUCTION_REFLECTION = MyClass.class.getDeclaredConstructor(String.class);
      CONSTRUCTION_REFLECTION.setAccessible(true);
      final Constructor<MyClass> constructor = MyClass.class.getDeclaredConstructor(String.class);
      constructor.setAccessible(true);
      CONSTRUCTION_UNREFLECTION = MethodHandles.lookup().unreflectConstructor(constructor);
    } catch (NoSuchMethodException e) {
      //
    } catch (IllegalAccessException e) {
      //
    }
  }

  public static void main(String[] args) throws RunnerException {
    Options opt =
        new OptionsBuilder()
            .include(ReflectionUnReflectionBenchmark.class.getSimpleName())
            .forks(1)
            .build();
    new Runner(opt).run();
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void unReflection() throws Throwable {
    MyClass myClass = (MyClass) CONSTRUCTION_UNREFLECTION.invoke("HELO");
    assert myClass.getParam().equals("HELO");
  }

  @Warmup(iterations = 2) // Warmup Iteration = 3
  @Measurement(iterations = 3)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  public void reflection()
      throws InvocationTargetException, InstantiationException, IllegalAccessException {
    MyClass myClass = CONSTRUCTION_REFLECTION.newInstance("HELO");
    assert myClass.getParam().equals("HELO");
  }

  static final class MyClass extends MyAbstract {

    private MyClass(String param) {
      super(param);
    }
  }

  abstract static class MyAbstract {

    private final String param;

    protected MyAbstract(String param) {
      this.param = param;
    }

    public String getParam() {
      return param;
    }
  }
}
