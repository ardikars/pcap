/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.common.logging;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class MessageFormatterTest {

  @Test
  public void newInstanceTest() {
    MessageFormatter formatter = new MessageFormatter();
    Assertions.assertNotNull(formatter);
  }

  @Test
  public void formatTest() {
    Object[] objects = new String[] {"World", "!"};
    FormattingTuple tuple;
    tuple = MessageFormatter.format(null, objects);
    Assertions.assertNull(tuple.getMessage());
    Assertions.assertEquals(objects, tuple.getArgArray()[0]);
    Assertions.assertNull(tuple.getThrowable());
    tuple = MessageFormatter.format("Hello", null);
    Assertions.assertEquals("Hello", tuple.getMessage());
    Assertions.assertNull(tuple.getArgArray()[0]);
    Assertions.assertNull(tuple.getThrowable());
    tuple = MessageFormatter.format("Hello", new RuntimeException());
    Assertions.assertEquals("Hello", tuple.getMessage());
    Assertions.assertNotNull(tuple.getArgArray());
    Assertions.assertNotNull(tuple.getThrowable());
    tuple = MessageFormatter.format("Hello {} {}", "Java", "World!");
    Assertions.assertEquals("Hello Java World!", tuple.getMessage());
    Assertions.assertNotNull(tuple.getArgArray());
    Assertions.assertNull(tuple.getThrowable());
  }

  @Test
  public void getThrowableCandidateTest() {
    Assertions.assertNull(MessageFormatter.getThrowableCandidate(null));
    Assertions.assertNull(MessageFormatter.getThrowableCandidate(new Object[0]));
    Assertions.assertNull(MessageFormatter.getThrowableCandidate(new String[] {"Hello"}));
    Assertions.assertNotNull(
        MessageFormatter.getThrowableCandidate(new RuntimeException[] {new RuntimeException()}));
  }

  @Test
  public void trimmedCopyTest() {
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MessageFormatter.trimmedCopy(null);
          }
        });
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            MessageFormatter.trimmedCopy(new Object[0]);
          }
        });
    Assertions.assertNotNull(MessageFormatter.trimmedCopy(new Object[] {new RuntimeException()}));
  }

  @Test
  public void arrayFormatTest() {
    Object[] objects = new String[] {"World", "!"};
    FormattingTuple tuple;
    tuple = MessageFormatter.arrayFormat("Hello {}{}", objects);
    Assertions.assertEquals("Hello World!", tuple.getMessage());
    Assertions.assertEquals(objects, tuple.getArgArray());
    Assertions.assertNull(tuple.getThrowable());
    tuple = MessageFormatter.arrayFormat("Hello", null, new RuntimeException());
    Assertions.assertEquals("Hello", tuple.getMessage());
    Assertions.assertNull(tuple.getArgArray());
    Assertions.assertNull(tuple.getThrowable());
    tuple = MessageFormatter.arrayFormat("Hello", null, new RuntimeException());
    Assertions.assertEquals("Hello", tuple.getMessage());
    Assertions.assertNull(tuple.getArgArray());
    Assertions.assertNull(tuple.getThrowable());
    tuple = MessageFormatter.arrayFormat("Hello {} x", objects, new RuntimeException());
    Assertions.assertEquals("Hello World x", tuple.getMessage());
    Assertions.assertEquals(objects, tuple.getArgArray());
    Assertions.assertNotNull(tuple.getThrowable());
    tuple = MessageFormatter.arrayFormat("Hello {} x \\{}", objects, new RuntimeException());
    Assertions.assertEquals("Hello World x {}", tuple.getMessage());
    Assertions.assertEquals(objects, tuple.getArgArray());
    Assertions.assertNotNull(tuple.getThrowable());
    tuple = MessageFormatter.arrayFormat("Hello {} x \\\\{}", objects, new RuntimeException());
    Assertions.assertEquals("Hello World x \\!", tuple.getMessage());
    Assertions.assertEquals(objects, tuple.getArgArray());
    Assertions.assertNotNull(tuple.getThrowable());
  }

  @Test
  public void isEscapedDelimeterTest() {
    Assertions.assertTrue(MessageFormatter.isEscapedDelimeter("\\", 1));
    Assertions.assertFalse(MessageFormatter.isEscapedDelimeter("\\", 0));
  }

  @Test
  public void isDoubleEscapedTest() {
    Assertions.assertTrue(MessageFormatter.isDoubleEscaped("\\", 2));
    Assertions.assertFalse(MessageFormatter.isDoubleEscaped("\\", 0));
    Assertions.assertFalse(MessageFormatter.isDoubleEscaped("HI", 2));
  }

  @Test
  public void deeplyAppendParameterTest() {
    List<String> lists = Arrays.asList("Hello", "World", "!");
    Unsafe unsafe = new Unsafe();
    Object[] objects = new String[] {"Hello", "World", "!"};
    boolean[] booleans = new boolean[] {true, true, true, false, false};
    byte[] bytes = new byte[] {0, 1, 2, 3, 4};
    char[] chars = new char[] {'a', 'b', 'c', 'd', 'e'};
    short[] shorts = new short[] {0, 1, 2, 3, 4};
    int[] ints = new int[] {0, 1, 2, 3, 4};
    long[] longs = new long[] {0L, 1L, 2L, 3L, 4L};
    float[] floats = new float[] {0.5F, 1.5F, 2.5F, 3.5F, 4.5F};
    double[] doubles = new double[] {0.5D, 1.5D, 2.5D, 3.5D, 4.5D};

    StringBuilder sb;
    Map<Object[], Object> seenMap;

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, null, seenMap);
    Assertions.assertEquals("null", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, lists, seenMap);
    Assertions.assertEquals("[Hello, World, !]", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, unsafe, seenMap);
    Assertions.assertEquals("[FAILED toString()]", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, objects, seenMap);
    Assertions.assertEquals("[Hello, World, !]", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, booleans, seenMap);
    Assertions.assertEquals("[true, true, true, false, false]", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, bytes, seenMap);
    Assertions.assertEquals("[0, 1, 2, 3, 4]", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, chars, seenMap);
    Assertions.assertEquals("[a, b, c, d, e]", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, shorts, seenMap);
    Assertions.assertEquals("[0, 1, 2, 3, 4]", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, ints, seenMap);
    Assertions.assertEquals("[0, 1, 2, 3, 4]", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, longs, seenMap);
    Assertions.assertEquals("[0, 1, 2, 3, 4]", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, floats, seenMap);
    Assertions.assertEquals("[0.5, 1.5, 2.5, 3.5, 4.5]", sb.toString());

    sb = new StringBuilder();
    seenMap = new HashMap<>();
    MessageFormatter.deeplyAppendParameter(sb, doubles, seenMap);
    Assertions.assertEquals("[0.5, 1.5, 2.5, 3.5, 4.5]", sb.toString());
  }

  @Test
  public void safeObjectAppendTest() {
    StringBuilder sb = new StringBuilder();
    List<String> value = Arrays.asList("Hello", "World", "!");
    MessageFormatter.safeObjectAppend(sb, value);
    Assertions.assertEquals("[Hello, World, !]", sb.toString());
    sb = new StringBuilder();
    Unsafe unsafe = new Unsafe();
    MessageFormatter.safeObjectAppend(sb, unsafe);
    Assertions.assertEquals("[FAILED toString()]", sb.toString());
  }

  @Test
  public void objectArrayAppendTest() {
    StringBuilder sb = new StringBuilder();
    Map<Object[], Object> seenMap = new HashMap<>();
    Object[] value = new String[] {"Hello", "World", "!"};
    MessageFormatter.objectArrayAppend(sb, value, seenMap);
    Assertions.assertEquals("[Hello, World, !]", sb.toString());

    sb = new StringBuilder();
    seenMap.put(value, "Whoa!");
    MessageFormatter.objectArrayAppend(sb, value, seenMap);
    Assertions.assertEquals("[...]", sb.toString());
  }

  @Test
  public void booleanArrayAppendTest() {
    StringBuilder sb = new StringBuilder();
    boolean[] value = new boolean[] {true, true, true, false, false};
    MessageFormatter.booleanArrayAppend(sb, value);
    Assertions.assertEquals("[true, true, true, false, false]", sb.toString());
  }

  @Test
  public void byteArrayAppendTest() {
    StringBuilder sb = new StringBuilder();
    byte[] value = new byte[] {0, 1, 2, 3, 4};
    MessageFormatter.byteArrayAppend(sb, value);
    Assertions.assertEquals("[0, 1, 2, 3, 4]", sb.toString());
  }

  @Test
  public void charArrayAppendTest() {
    StringBuilder sb = new StringBuilder();
    char[] value = new char[] {'a', 'b', 'c', 'd', 'e'};
    MessageFormatter.charArrayAppend(sb, value);
    Assertions.assertEquals("[a, b, c, d, e]", sb.toString());
  }

  @Test
  public void shortArrayAppendTest() {
    StringBuilder sb = new StringBuilder();
    short[] value = new short[] {0, 1, 2, 3, 4};
    MessageFormatter.shortArrayAppend(sb, value);
    Assertions.assertEquals("[0, 1, 2, 3, 4]", sb.toString());
  }

  @Test
  public void intArrayAppendTest() {
    StringBuilder sb = new StringBuilder();
    int[] value = new int[] {0, 1, 2, 3, 4};
    MessageFormatter.intArrayAppend(sb, value);
    Assertions.assertEquals("[0, 1, 2, 3, 4]", sb.toString());
  }

  @Test
  public void longArrayAppendTest() {
    StringBuilder sb = new StringBuilder();
    long[] value = new long[] {0L, 1L, 2L, 3L, 4L};
    MessageFormatter.longArrayAppend(sb, value);
    Assertions.assertEquals("[0, 1, 2, 3, 4]", sb.toString());
  }

  @Test
  public void floatArrayAppendTest() {
    StringBuilder sb = new StringBuilder();
    float[] value = new float[] {0.5F, 1.5F, 2.5F, 3.5F, 4.5F};
    MessageFormatter.floatArrayAppend(sb, value);
    Assertions.assertEquals("[0.5, 1.5, 2.5, 3.5, 4.5]", sb.toString());
  }

  @Test
  public void doubleArrayAppendTest() {
    StringBuilder sb = new StringBuilder();
    double[] value = new double[] {0.5D, 1.5D, 2.5D, 3.5D, 4.5D};
    MessageFormatter.doubleArrayAppend(sb, value);
    Assertions.assertEquals("[0.5, 1.5, 2.5, 3.5, 4.5]", sb.toString());
  }

  static class Unsafe {
    @Override
    public String toString() {
      throw new UnsupportedOperationException();
    }
  }
}
