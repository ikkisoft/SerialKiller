/*
 * SerialKiller.java
 *
 * Copyright (c) 2015 Luca Carettoni
 *
 * Easy to use library to secure Java deserialization from untrusted input.
 *
 * Dual-Licensed Software:
 *   [Apache V2.0]
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the LICENSE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *   [GPL V2.0]
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version. This program is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY.
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

public class SerialKiller extends ObjectInputStream
{

    private final XMLConfiguration config;

    public SerialKiller(InputStream inputStream, String configFile) throws IOException, ConfigurationException
    {
        super(inputStream);
        config = new XMLConfiguration(configFile);
        FileChangedReloadingStrategy reloadStrategy = new FileChangedReloadingStrategy();
        reloadStrategy.setRefreshDelay(config.getLong("refresh"));
        config.setReloadingStrategy(reloadStrategy);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass serialInput) throws IOException, ClassNotFoundException
    {
        String[] blacklist = config.getStringArray("blacklist.regexp");
        String[] whitelist = config.getStringArray("whitelist.regexp");

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
