/*
 * SerialKiller.java
 *
 * Copyright (c) 2015-2016 Luca Carettoni
 *
 * SerialKiller is an easy-to-use look-ahead Java deserialization library
 * to secure application from untrusted input. When Java serialization is
 * used to exchange information between a client and a server, attackers
 * can replace the legitimate serialized stream with malicious data.
 * SerialKiller inspects Java classes during naming resolution and allows
 * a combination of blacklisting/whitelisting to secure your application.
 *
 * Dual-Licensed Software: Apache v2.0 and GPL v2.0
 */
package org.nibblesec.tools;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Map;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class SerialKiller extends ObjectInputStream {

    private static final Log LOGGER = LogFactory.getLog(SerialKiller.class.getName());

    private static final Map<String, Configuration> configs = new ConcurrentHashMap<>();

    private final Configuration config;
    private final boolean profiling;

    /**
     * SerialKiller constructor, returns instance of ObjectInputStream.
     *
     * @param inputStream The original InputStream, used by your service to receive serialized objects
     * @param configFile The location of the config file (absolute path)
     * @throws java.io.IOException File I/O exception
     * @throws IllegalStateException Invalid configuration exception
     */
    public SerialKiller(final InputStream inputStream, final String configFile) throws IOException {
        super(inputStream);

        config = configs.computeIfAbsent(configFile, Configuration::new);
        profiling = config.isProfiling();
    }

    @Override
    protected Class<?> resolveClass(final ObjectStreamClass serialInput) throws IOException, ClassNotFoundException {
        config.reloadIfNeeded();

        // Enforce SerialKiller's blacklist
        for (Pattern blackPattern : config.blacklist()) {
            Matcher blackMatcher = blackPattern.matcher(serialInput.getName());

            if (blackMatcher.find()) {
                if (profiling) {
                    // Reporting mode
                    LOGGER.info(String.format("Blacklist match: '%s'", serialInput.getName()));
                } else {
                    // Blocking mode
                    LOGGER.error(String.format("Blocked by blacklist '%s'. Match found for '%s'", blackPattern.pattern(), serialInput.getName()));
                    throw new InvalidClassException(serialInput.getName(), "Class blocked from deserialization (blacklist)");
                }
            }
        }

        // Enforce SerialKiller's whitelist
        boolean safeClass = false;

        for (Pattern whitePattern : config.whitelist()) {
            Matcher whiteMatcher = whitePattern.matcher(serialInput.getName());

            if (whiteMatcher.find()) {
                safeClass = true;

                if (profiling) {
                    // Reporting mode
                    LOGGER.info(String.format("Whitelist match: '%s'", serialInput.getName()));
                }

                // We have found a whitelist match, no need to continue
                break;
            }
        }

        if (!safeClass && !profiling) {
            // Blocking mode
            LOGGER.error(String.format("Blocked by whitelist. No match found for '%s'", serialInput.getName()));
            throw new InvalidClassException(serialInput.getName(), "Class blocked from deserialization (non-whitelist)");
        }

        return super.resolveClass(serialInput);
    }

    static final class Configuration {
        private final XMLConfiguration config;

        private List<Pattern> blacklist;
        private List<Pattern> whitelist;

        Configuration(final String configPath) {
            try {
                config = new XMLConfiguration(configPath);

                FileChangedReloadingStrategy reloadStrategy = new FileChangedReloadingStrategy();
                reloadStrategy.setRefreshDelay(config.getLong("refresh", 6000));
                config.setReloadingStrategy(reloadStrategy);
                config.addConfigurationListener(event -> init(config));

                init(config);
            } catch (ConfigurationException | PatternSyntaxException e) {
                throw new IllegalStateException("SerialKiller not properly configured: " + e.getMessage(), e);
            }
        }

        private void init(XMLConfiguration config) {
            blacklist = Stream.of(config.getStringArray("blacklist.regexps.regexp"))
                .map(Pattern::compile)
                .collect(Collectors.toList());
            whitelist = Stream.of(config.getStringArray("whitelist.regexps.regexp"))
                .map(Pattern::compile)
                .collect(Collectors.toList());
        }

        void reloadIfNeeded() {
            // NOTE: Unfortunately, this will invoke synchronized blocks in Commons Configuration
            config.reload();
        }

        Iterable<Pattern> blacklist() {
            return blacklist;
        }

        Iterable<Pattern> whitelist() {
            return whitelist;
        }

        boolean isProfiling() {
            return config.getBoolean("mode.profiling", false);
        }
    }
}