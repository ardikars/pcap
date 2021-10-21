/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Restricted function.
 *
 * <p>Calling method annotated with @{@link Restricted} will throws {@link IllegalAccessException}
 * unless you set a "pcap.restricted" property with a value other then deny. The possible values for
 * this property are:
 *
 * <ul>
 *   <li>deny: issues a runtime exception on each restricted call. This is the default value.
 *   <li>permit: allows restricted calls.
 *   <li>warn: like permit, but also prints a one-line warning on each restricted call.
 * </ul>
 *
 * @since 1.3.1
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Restricted {}
