/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Reflections {

  private static final boolean ACCESS_CONTROL;

  public static Throwable trySetAccessible(
      final AccessibleObject object, final boolean checkAccessible) throws RuntimeException {
    if (checkAccessible && !ACCESS_CONTROL) {
      return new UnsupportedOperationException("Reflective setAccessible(true) disabled");
    }
    return setAccessible(object, checkAccessible);
  }

  public static Throwable forceSetAccessible(
      final AccessibleObject object, final boolean checkAccessible) throws RuntimeException {
    return setAccessible(object, checkAccessible);
  }

  /**
   * Gets a {@code List} of superclasses for the given class.
   *
   * @param cls the class to look up.
   * @return returns {@code List} of superclasses.
   */
  public static List<Class<?>> getAllSuperClasses(final Class<?> cls) {
    Validate.notIllegalArgument(cls != null, "Class should be not null");
    final List<Class<?>> classes = new ArrayList<Class<?>>();
    Class<?> superclass = cls.getSuperclass();
    while (superclass != null) {
      classes.add(superclass);
      superclass = superclass.getSuperclass();
    }
    return Collections.unmodifiableList(classes);
  }

  /**
   * Gets a {@code List} of superclasses and class it self for the given class.
   *
   * @param cls the class to look up.
   * @return returns {@code List} of superclasses and class it self.
   */
  public static List<Class<?>> getAllClasses(final Class<?> cls) {
    Validate.notIllegalArgument(cls != null, "Class should be not null");
    final List<Class<?>> classes = new ArrayList<Class<?>>();
    classes.add(cls);
    classes.addAll(getAllSuperClasses(cls));
    return Collections.unmodifiableList(classes);
  }

  /**
   * Gets a {@code List} of all interfaces implemented by the given class and its superclasses.
   *
   * @param cls the class to look up.
   * @return returns {@code List} of interfaces.
   */
  public static List<Class<?>> getAllInterfaces(final Class<?> cls) {
    Validate.notIllegalArgument(cls != null, "Class should be not null");
    List<Class<?>> classes = getAllClasses(cls);
    Iterator<Class<?>> iterator = classes.iterator();
    List<Class<?>> interfaces = new ArrayList<Class<?>>();
    while (iterator.hasNext()) {
      Class<?> clazz = iterator.next();
      for (Class<?> i : clazz.getInterfaces()) {
        interfaces.add(i);
      }
    }
    return Collections.unmodifiableList(interfaces);
  }

  /**
   * Get a {@code List} of all classes and interfaces.
   *
   * @param cls the class to look up.
   * @return returns {@code List} of all classes and interfaces.
   */
  public static List<Class<?>> getAllClassesAndInterfaces(final Class<?> cls) {
    Validate.notIllegalArgument(cls != null, "Class should be not null");
    List<Class<?>> classes = new ArrayList<Class<?>>();
    classes.addAll(getAllClasses(cls));
    classes.addAll(getAllInterfaces(cls));
    return Collections.unmodifiableList(classes);
  }

  /**
   * Get a {@code List} of all super classes and interfaces.
   *
   * @param cls the class to look up.
   * @return returns {@code List} of all super classes and interfaces.
   */
  public static List<Class<?>> getAllSuperClassesAndInterfaces(final Class<?> cls) {
    Validate.notIllegalArgument(cls != null, "Class should be not null");
    final List<Class<?>> allSuperClassesAndInterfaces = new ArrayList<Class<?>>();
    final List<Class<?>> allSuperclasses = getAllSuperClasses(cls);
    int superClassIndex = 0;
    final List<Class<?>> allInterfaces = getAllInterfaces(cls);
    int interfaceIndex = 0;
    while (interfaceIndex < allInterfaces.size() || superClassIndex < allSuperclasses.size()) {
      Class<?> acls;
      if (interfaceIndex >= allInterfaces.size()) {
        acls = allSuperclasses.get(superClassIndex++);
      } else if (superClassIndex >= allSuperclasses.size()) {
        acls = allInterfaces.get(interfaceIndex++);
      } else if (interfaceIndex < superClassIndex) {
        acls = allInterfaces.get(interfaceIndex++);
      } else if (superClassIndex < interfaceIndex) {
        acls = allSuperclasses.get(superClassIndex++);
      } else {
        acls = allInterfaces.get(interfaceIndex++);
      }
      allSuperClassesAndInterfaces.add(acls);
    }
    return Collections.unmodifiableList(allSuperClassesAndInterfaces);
  }

  /**
   * Get public field from current or super class/interface.
   *
   * @param cls the class to look up.
   * @param fieldName field name.
   * @return returns {@link Field}.
   * @throws NoSuchFieldException field not found.
   */
  public static Field getPublicFiled(final Class<?> cls, String fieldName)
      throws NoSuchFieldException {
    final Field declaredField = cls.getField(fieldName);
    if (Modifier.isPublic(declaredField.getDeclaringClass().getModifiers())) {
      return declaredField;
    }
    final List<Class<?>> candidateClasses = getAllSuperClassesAndInterfaces(cls);
    for (final Class<?> candidateClass : candidateClasses) {
      if (!Modifier.isPublic(candidateClass.getModifiers())) {
        continue;
      }
      Field candidateField;
      try {
        candidateField = candidateClass.getField(fieldName);
      } catch (final NoSuchFieldException ex) {
        continue;
      }
      if (Modifier.isPublic(candidateField.getDeclaringClass().getModifiers())) {
        return candidateField;
      }
    }
    throw new NoSuchFieldException("Can't find a public field for " + fieldName);
  }

  /**
   * Get public method from current or super class/interface.
   *
   * @param cls the class to look up.
   * @param methodName method name.
   * @param parameterTypes parameter types.
   * @return returns {@link Method}.
   * @throws NoSuchMethodException method not found.
   */
  public static Method getPublicMethod(
      final Class<?> cls, final String methodName, final Class<?>... parameterTypes)
      throws NoSuchMethodException {
    final Method declaredMethod = cls.getMethod(methodName, parameterTypes);
    if (Modifier.isPublic(declaredMethod.getDeclaringClass().getModifiers())) {
      return declaredMethod;
    }
    final List<Class<?>> candidateClasses = getAllSuperClassesAndInterfaces(cls);
    for (final Class<?> candidateClass : candidateClasses) {
      if (!Modifier.isPublic(candidateClass.getModifiers())) {
        continue;
      }
      Method candidateMethod;
      try {
        candidateMethod = candidateClass.getMethod(methodName, parameterTypes);
      } catch (final NoSuchMethodException ex) {
        continue;
      }
      if (Modifier.isPublic(candidateMethod.getDeclaringClass().getModifiers())) {
        return candidateMethod;
      }
    }
    throw new NoSuchMethodException(
        "Can't find a public method for " + methodName + " " + Arrays.toString(parameterTypes));
  }

  private static Throwable setAccessible(
      final AccessibleObject object, final boolean checkAccessible) throws RuntimeException {
    Object obj =
        AccessController.doPrivileged(
            new PrivilegedAction<Object>() {
              @Override
              public Object run() {
                try {
                  object.setAccessible(checkAccessible);
                  return null;
                } catch (SecurityException e) {
                  return e;
                } catch (RuntimeException e) {
                  return e;
                }
              }
            });
    if (obj == null) {
      return null;
    } else {
      return (Throwable) obj;
    }
  }

  /**
   * Is the specified class an inner class or static nested class.
   *
   * @param cls the class to check, may be null.
   * @return {@code true} if the class is an inner or static nested class, false if not or {@code
   *     null}
   */
  public static boolean isInnerClass(final Class<?> cls) {
    return cls != null && cls.getEnclosingClass() != null;
  }

  static {
    ACCESS_CONTROL = Properties.getBoolean("pcap.reflection", Platforms.javaMojorVersion() < 9);
  }
}
