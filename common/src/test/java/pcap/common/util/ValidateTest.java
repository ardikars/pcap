/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** */
@RunWith(JUnitPlatform.class)
public class ValidateTest {

  @Test
  public void nullPointerTest() {
    Validate.nullPointer("");
    Assertions.assertThrows(
        NullPointerException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.nullPointer(null);
          }
        });
    Validate.nullPointer("", "OK");
    Assertions.assertThrows(
        NullPointerException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.nullPointer(null, "NOK");
          }
        });
    Assertions.assertEquals("OK", Validate.nullPointerThenReturns(null, "OK"));
    Assertions.assertEquals("YES", Validate.nullPointerThenReturns("YES", "OK"));
  }

  @Test
  public void notIllegalArgumentTest() {
    Validate.notIllegalArgument(true);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notIllegalArgument(false);
          }
        });
    Validate.notIllegalArgument(true, "OK");
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notIllegalArgument(false, "NOK");
          }
        });
    Assertions.assertEquals("OK", Validate.notIllegalArgumentThenReturns(false, "NOK", "OK"));
    Assertions.assertEquals("OK", Validate.notIllegalArgumentThenReturns(true, "OK", "NOK"));
  }

  @Test
  public void notIllegalStateTest() {
    Validate.notIllegalState(true);
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notIllegalState(false);
          }
        });
    Validate.notIllegalState(true, "OK");
    Assertions.assertThrows(
        IllegalStateException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notIllegalState(false, "NOK");
          }
        });
    Assertions.assertEquals("OK", Validate.notIllegaStateThenReturns(false, "NOK", "OK"));
    Assertions.assertEquals("OK", Validate.notIllegaStateThenReturns(true, "OK", "NOK"));
  }

  @Test
  public void notInBoundsTestBytes() {
    final byte[] data = new byte[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(new byte[0], 0, 3);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, -1, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 6, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, -1);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, 6);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 5, 5);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 3, 3);
          }
        });

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestChars() {
    final char[] data = new char[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(new char[0], 0, 3);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, -1, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 6, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, -1);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, 6);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 5, 5);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 3, 3);
          }
        });

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestShorts() {
    final short[] data = new short[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(new short[0], 0, 3);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, -1, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 6, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, -1);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, 6);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 5, 5);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 3, 3);
          }
        });

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestInts() {
    final int[] data = new int[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(new int[0], 0, 3);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, -1, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 6, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, -1);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, 6);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 5, 5);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 3, 3);
          }
        });

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestFloats() {
    final float[] data = new float[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(new float[0], 0, 3);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, -1, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 6, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, -1);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, 6);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 5, 5);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 3, 3);
          }
        });

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestLongs() {
    final long[] data = new long[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(new long[0], 0, 3);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, -1, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 6, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, -1);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, 6);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 5, 5);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 3, 3);
          }
        });

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestDoubles() {
    final double[] data = new double[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(new double[0], 0, 3);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, -1, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 6, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, -1);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, 6);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 5, 5);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 3, 3);
          }
        });

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestObjects() {
    final Object[] data = new Object[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(new Object[0], 0, 3);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, -1, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 6, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, -1);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, 6);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 5, 5);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 3, 3);
          }
        });

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTest() {
    final int data = 5;
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(0, 0, 3);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, -1, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 6, 5);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, -1);
          }
        });
    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 0, 6);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(data, 5, 5);
          }
        });

    Assertions.assertThrows(
        ArrayIndexOutOfBoundsException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Validate.notInBounds(10, 5, 6);
          }
        });

    Validate.notInBounds(data, 0, 5);
  }
}
