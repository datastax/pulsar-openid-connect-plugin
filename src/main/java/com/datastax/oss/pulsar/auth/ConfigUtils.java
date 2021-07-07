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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public class ConfigUtils {
    private static final Logger log = LoggerFactory.getLogger(ConfigUtils.class);

    /**
     * Get configured property as a string. If not configured, return null.
     * @param conf - the configuration map
     * @param configProp - the property to get
     * @return a string from the conf
     */
    public static String getConfigValueAsString(ServiceConfiguration conf, String configProp) throws IllegalArgumentException {
        String value = getConfigValueAsStringImpl(conf, configProp);
        log.info("Configuration for [{}] is [{}]", configProp, value);
        return value;
    }

    /**
     * Get configured property as a set. Split using a comma delimiter and remove any extra whitespace surrounding
     * the commas. If not configured, return the empty set.
     *
     * @param conf - the map of configuration properties
     * @param configProp - the property (key) to get
     * @return a set of strings from the conf
     */
    public static Set<String> getConfigValueAsSet(ServiceConfiguration conf, String configProp) {
        String value = getConfigValueAsStringImpl(conf, configProp);
        if (value == null) {
            log.info("Configuration for [{}] is the empty set.", configProp);
            return Collections.emptySet();
        }
        Set<String> set = Arrays.stream(value.trim().split("\\s*,\\s*")).collect(Collectors.toSet());
        log.info("Configuration for [{}] is [{}].", configProp, String.join(", ", set));
        return set;
    }

    private static String getConfigValueAsStringImpl(ServiceConfiguration conf, String configProp) throws IllegalArgumentException {
        Object value = conf.getProperty(configProp);
        if (value instanceof String) {
            return (String) value;
        } else {
            return null;
        }
    }

    /**
     * Utility method to get a long from the {@link ServiceConfiguration}. If the value is not a valid long or the key
     * is not present in the conf, the default value will be used.
     *
     * @param conf - the map of configuration properties
     * @param configProp - the property (key) to get
     * @param defaultValue - the value to use if the property is missing from the conf
     * @return a long
     */
    public static long getConfigValueAsLong(ServiceConfiguration conf, String configProp, long defaultValue) {
        Object value = conf.getProperty(configProp);
        if (value instanceof Long) {
            log.info("Configuration for [{}] is [{}]", configProp, value);
            return (Long) value;
        } else if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException numberFormatException) {
                log.error("Expected configuration for [{}] to be a long, but got [{}]. Using default value: [{}]", configProp, value, defaultValue, numberFormatException);
                return defaultValue;
            }
        } else {
            log.info("Configuration for [{}] is using the default value: [{}]", configProp, defaultValue);
            return defaultValue;
        }
    }

    /**
     * Utility method to get a boolean from the {@link ServiceConfiguration}. If the key is present in the conf,
     * return the default value. If key is present the value is not a valid boolean, the result will be false.
     *
     * @param conf - the map of configuration properties
     * @param configProp - the property (key) to get
     * @param defaultValue - the value to use if the property is missing from the conf
     * @return a boolean
     */
    public static boolean getConfigValueAsBoolean(ServiceConfiguration conf, String configProp, boolean defaultValue) {
        Object value = conf.getProperty(configProp);
        if (value instanceof Boolean) {
            log.info("Configuration for [{}] is [{}]", configProp, value);
            return (boolean) value;
        } else if (value instanceof String) {
            boolean result = Boolean.parseBoolean((String) value);
            log.info("Configuration for [{}] is [{}]", configProp, result);
            return result;
        } else {
            log.info("Configuration for [{}] is using the default value: [{}]", configProp, defaultValue);
            return defaultValue;
        }
    }
}