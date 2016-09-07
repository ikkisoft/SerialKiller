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
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;

public class SerialKiller extends ObjectInputStream {

    private final XMLConfiguration config;
    private final FileChangedReloadingStrategy reloadStrategy;
    private static final Logger LOGGER = Logger.getLogger(SerialKiller.class.getName());
    private static Handler fileHandler;
    private static String logFile;
    private static boolean logEnabled;
    private static String[] blacklist;
    private static String[] whitelist;
    private static boolean profiling;    

    /**
     * SerialKiller constructor, returns instance of ObjectInputStream
     *
     * @param inputStream The original InputStream, used by your service to receive serialized objects
     * @param configFile The location of the config file (absolute path)
     * @throws java.io.IOException File I/O exception
     * @throws org.apache.commons.configuration.ConfigurationException Config exception
     */
    public SerialKiller(InputStream inputStream, String configFile) throws IOException, ConfigurationException {
        
        super(inputStream);
        
        config = new XMLConfiguration(configFile);
        reloadStrategy = new FileChangedReloadingStrategy();
        //To avoid permanent disc access on successive property lookups 
        reloadStrategy.setRefreshDelay(config.getLong("refresh", 6000));
        config.setReloadingStrategy(reloadStrategy);
        
        blacklist = config.getStringArray("blacklist.regexp");
        whitelist = config.getStringArray("whitelist.regexp");
        profiling = config.getBoolean("mode.profiling", false);
        logEnabled = config.getBoolean("logging.enabled", true);        
   
        if(logEnabled){
            logFile = config.getString("logging.logfile", "/tmp/serialkiller.log");
            fileHandler  = new FileHandler(logFile, true);
            LOGGER.addHandler(fileHandler);
            LOGGER.setLevel(Level.ALL);
        }
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass serialInput) throws IOException, ClassNotFoundException {

        //Enforce SerialKiller's blacklist
        for (String blackRegExp : blacklist) {
            Pattern blackPattern = Pattern.compile(blackRegExp);
            Matcher blackMatcher = blackPattern.matcher(serialInput.getName());
            if (blackMatcher.find()) {
                if (profiling){
                    //Reporting mode 
                    LOGGER.log(Level.FINE, "Blacklist match: ''{0}''", serialInput.getName());
                }else{
                    //Blocking mode
                    LOGGER.log(Level.SEVERE, "Blocked by blacklist ''{0}''. Match found for ''{1}''", new Object[]{blackRegExp, serialInput.getName()});
                    throw new InvalidClassException("Class blocked by SK: '" + serialInput.getName() + "'");
                }
            }
        }

        //Enforce SerialKiller's whitelist
        boolean safeClass = false;
        for (String whiteRegExp : whitelist) {
            Pattern whitePattern = Pattern.compile(whiteRegExp);
            Matcher whiteMatcher = whitePattern.matcher(serialInput.getName());
            if (whiteMatcher.find()) {
                safeClass = true;
                
                if (profiling){
                    //Reporting mode 
                    LOGGER.log(Level.FINE, "Whitelist match: ''{0}''", serialInput.getName());
                }
            }
        }
        if (!safeClass && !profiling) {
            //Blocking mode
            LOGGER.log(Level.SEVERE, "Blocked by whitelist. No match found for ''{0}''", serialInput.getName());
            throw new InvalidClassException("Class blocked by SK: '" + serialInput.getName() + "'");
        }

        return super.resolveClass(serialInput);
    }
}