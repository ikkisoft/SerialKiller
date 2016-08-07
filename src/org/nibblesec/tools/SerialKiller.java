/**
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
 *
 */
package org.nibblesec.tools;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;

public class SerialKiller extends ObjectInputStream {

    private final XMLConfiguration config;
    private final FileChangedReloadingStrategy reloadStrategy;
    private static String[] blacklist;
    private static String[] whitelist;

    /**
     * SerialKiller constructor, returns instance of ObjectInputStream
     *
     * @param inputStream The original InputStream, used by your service to receive serialized objects
     * @param configFile The location of the config file (absolute path)
     * @throws IOException ConfigurationException
     */
    public SerialKiller(InputStream inputStream, String configFile) throws IOException, ConfigurationException {
        
        super(inputStream);
        config = new XMLConfiguration(configFile);
        reloadStrategy = new FileChangedReloadingStrategy();
        //To avoid permanent disc access on successive property lookups 
        reloadStrategy.setRefreshDelay(config.getLong("refresh"));
        config.setReloadingStrategy(reloadStrategy);
        blacklist = config.getStringArray("blacklist.regexp");
        whitelist = config.getStringArray("whitelist.regexp");
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass serialInput) throws IOException, ClassNotFoundException {

        if (reloadStrategy.reloadingRequired()) {
            blacklist = config.getStringArray("blacklist.regexp");
            whitelist = config.getStringArray("whitelist.regexp");
        }

        //Enforce SerialKiller's blacklist
        for (String blackRegExp : blacklist) {
            Pattern blackPattern = Pattern.compile(blackRegExp);
            Matcher blackMatcher = blackPattern.matcher(serialInput.getName());
            if (blackMatcher.find()) {
                throw new InvalidClassException("[!] Blocked by SerialKiller's blacklist '" + blackRegExp + "'. Match found for '" + serialInput.getName() + "'");
            }
        }

        //Enforce SerialKiller's whitelist
        boolean safeClass = false;
        for (String whiteRegExp : whitelist) {
            Pattern whitePattern = Pattern.compile(whiteRegExp);
            Matcher whiteMatcher = whitePattern.matcher(serialInput.getName());
            if (whiteMatcher.find()) {
                safeClass = true;
            }
        }
        if (!safeClass) {
            throw new InvalidClassException("[!] Blocked by SerialKiller's whitelist. No match found for '" + serialInput.getName() + "'");
        }

        return super.resolveClass(serialInput);
    }
}
