/*
 * Copyright DataStax, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.datastax.oss.pulsar.auth;

import org.apache.pulsar.broker.ServiceConfiguration;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Properties;
import java.util.Set;

public class ConfigUtilsTest {


    @Test
    public void testGetConfigValueAsStringWorks() {
        Properties props = new Properties();
        props.setProperty("prop1", "audience");
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        String actual = ConfigUtils.getConfigValueAsString(config, "prop1");
        Assertions.assertEquals("audience", actual);
    }

    @Test
    public void testGetConfigValueAsStringReturnsNullIfMissing() {
        Properties props = new Properties();
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        String actual = ConfigUtils.getConfigValueAsString(config, "prop1");
        Assertions.assertNull(actual);
    }

    @Test
    public void testGetConfigValueAsSetReturnsWorks() {
        Properties props = new Properties();
        props.setProperty("prop1", "a, b,   c");
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        Set<String> actual = ConfigUtils.getConfigValueAsSet(config, "prop1");
        // Trims all whitespace
        Assertions.assertEquals(Set.of("a", "b", "c"), actual);
    }

    @Test
    public void testGetConfigValueAsSetReturnsEmptySetIfMissing() {
        Properties props = new Properties();
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        Set<String> actual = ConfigUtils.getConfigValueAsSet(config, "prop1");
        Assertions.assertEquals(Collections.emptySet(), actual);
    }

    @Test
    public void testGetConfigValueAsLongWorks() {
        Properties props = new Properties();
        props.setProperty("prop1", "1234");
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        long actual = ConfigUtils.getConfigValueAsLong(config, "prop1", 9);
        Assertions.assertEquals(1234, actual);
    }

    @Test
    public void testGetConfigValueAsLongReturnsDefaultIfNAN() {
        Properties props = new Properties();
        props.setProperty("prop1", "non-a-number");
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        long actual = ConfigUtils.getConfigValueAsLong(config, "prop1", 9);
        Assertions.assertEquals(9, actual);
    }

    @Test
    public void testGetConfigValueAsLongReturnsDefaultIfMissingProp() {
        Properties props = new Properties();
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        long actual = ConfigUtils.getConfigValueAsLong(config, "prop1", 10);
        Assertions.assertEquals(10, actual);
    }

    @Test
    public void testGetConfigValueAsBooleanReturnsDefaultIfMissingProp() {
        Properties props = new Properties();
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        boolean actualFalse = ConfigUtils.getConfigValueAsBoolean(config, "prop1", false);
        Assertions.assertFalse(actualFalse);
        boolean actualTrue = ConfigUtils.getConfigValueAsBoolean(config, "prop1", true);
        Assertions.assertTrue(actualTrue);
    }

    @Test
    public void testGetConfigValueAsBooleanWorks() {
        Properties props = new Properties();
        props.setProperty("prop1", "true");
        ServiceConfiguration config = new ServiceConfiguration();
        config.setProperties(props);
        boolean actual = ConfigUtils.getConfigValueAsBoolean(config, "prop1", false);
        Assertions.assertTrue(actual);
    }

}
