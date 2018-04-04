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

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Map;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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

        final String serialInputName = serialInput.getName();

        if (!config.isSafeClass(serialInputName)) {
            checkSafeClass(serialInputName);
            config.addSafeClass(serialInputName);
        }

        return super.resolveClass(serialInput);
    }

    private void checkSafeClass(String serialInputName) throws InvalidClassException {
        // Enforce SerialKiller's blacklist
        checkBlackList(serialInputName);

        // Enforce SerialKiller's whitelist
        boolean isSafeClass = isCheckedClassInWhiteList(serialInputName);

        if (!isSafeClass && !profiling) {
            // Blocking mode
            LOGGER.error(String.format("Blocked by whitelist. No match found for '%s'", serialInputName));
            throw new InvalidClassException(serialInputName, "Class blocked from deserialization (non-whitelist)");
        }
    }

    private void checkBlackList(final String serialInputName) throws InvalidClassException {
        for (Pattern blackPattern : config.blacklist()) {
            Matcher blackMatcher = blackPattern.matcher(serialInputName);

            if (blackMatcher.find()) {
                if (profiling) {
                    // Reporting mode
                    LOGGER.info(String.format("Blacklist match: '%s'", serialInputName));
                } else {
                    // Blocking mode
                    LOGGER.error(String.format("Blocked by blacklist '%s'. Match found for '%s'", new Object[] {blackPattern.pattern(), serialInputName}));
                    throw new InvalidClassException(serialInputName, "Class blocked from deserialization (blacklist)");
                }
            }
        }
    }

    private boolean isCheckedClassInWhiteList(final String serialInputName) {
        for (Pattern whitePattern : config.whitelist()) {
            Matcher whiteMatcher = whitePattern.matcher(serialInputName);

            if (whiteMatcher.find()) {
                if (profiling) {
                    // Reporting mode
                    LOGGER.info(String.format("Whitelist match: '%s'", serialInputName));
                }

                // We have found a whitelist match, no need to continue
                return true;
            }
        }
        return false;
    }

    static final class Configuration {
        private final XMLConfiguration config;

        private PatternList blacklist;
        private PatternList whitelist;
        private Set<String> safeClassesSet = new HashSet<>();

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

        private void init(final XMLConfiguration config) {
            blacklist = new PatternList(config.getStringArray("blacklist.regexps.regexp"));
            whitelist = new PatternList(config.getStringArray("whitelist.regexps.regexp"));
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

        void addSafeClass(String className) {
            safeClassesSet.add(className);
        }

        boolean isSafeClass(String className) {
            return safeClassesSet.contains(className);
        }
    }

    static final class PatternList implements Iterable<Pattern> {
        private final Pattern[] patterns;

        PatternList(final String... regExps) {

            requireNonNull(regExps, "regExps");

            this.patterns = new Pattern[regExps.length];
            for (int i = 0; i < regExps.length; i++) {
                patterns[i] = Pattern.compile(regExps[i]);
            }
        }

        @Override
        public Iterator<Pattern> iterator() {
            return new Iterator<Pattern>() {
                int index = 0;

                @Override
                public boolean hasNext() {
                    return index < patterns.length;
                }

                @Override
                public Pattern next() {
                    return patterns[index++];
                }

                @Override
                public void remove() {
                    throw new UnsupportedOperationException("remove");
                }
            };
        }

        @Override
        public String toString() {
            return Arrays.toString(patterns);
        }

    }
}