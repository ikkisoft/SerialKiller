/**
 * SerialKiller.java
 * <p>
 * Copyright (c) 2015-2016 Luca Carettoni
 * <p>
 * SerialKiller is an easy-to-use look-ahead Java deserialization library
 * to secure application from untrusted input. When Java serialization is
 * used to exchange information between a client and a server, attackers
 * can replace the legitimate serialized stream with malicious data.
 * SerialKiller inspects Java classes during naming resolution and allows
 * a combination of blacklisting/whitelisting to secure your application.
 * <p>
 * Dual-Licensed Software: Apache v2.0 and GPL v2.0
 */
package org.nibblesec.tools;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.event.ConfigurationEvent;
import org.apache.commons.configuration.event.ConfigurationListener;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;

public class SerialKiller extends ObjectInputStream {
    // TODO: Fix config reload issues
    //       Move config out of this class?
    // TODO: Fix regexp caching (see own issue in upstream). Need to be done per config or globally.
    // TODO: Should SEVERE logs be WARNINGS?

    // DONE:
    // Fix static issues
    // Create tests!
    // Allow exception message to contain class name (proper way) + tell if it's a whitelist/blacklist hit?

    private final XMLConfiguration config;

    private static final Logger LOGGER = Logger.getLogger(SerialKiller.class.getName());

    private LazyPatternList blacklist;
    private LazyPatternList whitelist;

    private final boolean profiling;

    /**
     * SerialKiller constructor, returns instance of ObjectInputStream
     *
     * @param inputStream The original InputStream, used by your service to receive serialized objects
     * @param configFile The location of the config file (absolute path)
     * @throws java.io.IOException File I/O exception
     * @throws org.apache.commons.configuration.ConfigurationException Config exception
     */
    public SerialKiller(final InputStream inputStream, final String configFile) throws IOException, ConfigurationException {
        super(inputStream);

        config = new XMLConfiguration(configFile);

        // TODO: Is there anyone listening..?
        FileChangedReloadingStrategy reloadStrategy = new FileChangedReloadingStrategy();
        reloadStrategy.setRefreshDelay(config.getLong("refresh", 6000));
        config.setReloadingStrategy(reloadStrategy);

        // TODO: We need to get this from the common config for the caching to work...
        blacklist = new LazyPatternList(config.getStringArray("blacklist.regexp"));
        whitelist = new LazyPatternList(config.getStringArray("whitelist.regexp"));

        profiling = config.getBoolean("mode.profiling", false);

        boolean logEnabled = config.getBoolean("logging.enabled", true);

        if (logEnabled) {
            String logFile = config.getString("logging.logfile", "/tmp/serialkiller.log");
            // TODO: Do we need to do this in code?
            Handler fileHandler = new FileHandler(logFile, true);
            LOGGER.addHandler(fileHandler);
            LOGGER.setLevel(Level.ALL);
        }
    }

    @Override
    protected Class<?> resolveClass(final ObjectStreamClass serialInput) throws IOException, ClassNotFoundException {
        // Enforce SerialKiller's blacklist
        for (Pattern blackPattern : blacklist) {
            Matcher blackMatcher = blackPattern.matcher(serialInput.getName());

            if (blackMatcher.find()) {
                if (profiling) {
                    // Reporting mode
                    LOGGER.log(Level.FINE, "Blacklist match: ''{0}''", serialInput.getName());
                } else {
                    // Blocking mode
                    LOGGER.log(Level.SEVERE, "Blocked by blacklist ''{0}''. Match found for ''{1}''", new Object[]{blackPattern.pattern(), serialInput.getName()});
                    throw new InvalidClassException(serialInput.getName(), "Class blocked from deserialization (blacklist)");
                }
            }
        }

        // Enforce SerialKiller's whitelist
        boolean safeClass = false;

        for (Pattern whitePattern : whitelist) {
            Matcher whiteMatcher = whitePattern.matcher(serialInput.getName());

            if (whiteMatcher.find()) {
                safeClass = true;

                if (profiling) {
                    // Reporting mode
                    LOGGER.log(Level.FINE, "Whitelist match: ''{0}''", serialInput.getName());
                }

                // We have found a whitelist match, no need to continue
                break;
            }
        }

        if (!safeClass && !profiling) {
            // Blocking mode
            LOGGER.log(Level.SEVERE, "Blocked by whitelist. No match found for ''{0}''", serialInput.getName());
            throw new InvalidClassException(serialInput.getName(), "Class blocked from deserialization (non-whitelist)");
        }

        return super.resolveClass(serialInput);
    }

    static class LazyPatternList implements Iterable<Pattern> {
        private final String[] regExps;
        private final Pattern[] patterns;

        LazyPatternList(final String... regExps) {
            this.regExps = requireNonNull(regExps, "regExps");
            this.patterns = new Pattern[regExps.length];
        }

        @Override
        public Iterator<Pattern> iterator() {
            return new Iterator<Pattern>() {
                int index = 0;

                @Override
                public boolean hasNext() {
                    return index < regExps.length;
                }

                @Override
                public Pattern next() {
                    // TODO: Multithreading issue here? Need atomic op
                    if (patterns[index] == null) {
                        patterns[index] = Pattern.compile(regExps[index]);
                    }

                    return patterns[index++];
                }

                @Override
                public void remove() {
                    throw new UnsupportedOperationException("remove");
                }
            };
        }
    }
}