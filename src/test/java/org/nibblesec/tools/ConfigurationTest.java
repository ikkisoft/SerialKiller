package org.nibblesec.tools;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;

import org.junit.Test;
import org.nibblesec.tools.SerialKiller.Configuration;

/**
 * ConfigurationTest
 */
public class ConfigurationTest {
    @Test(expected = IllegalStateException.class)
    public void testCreateNull() {
        new Configuration(null);
    }

    @Test(expected = IllegalStateException.class)
    public void testCreateNonExistant() {
        new Configuration("/i/am/pretty-sure/this-file/does-not-exist");
    }

    @Test(expected = IllegalStateException.class)
    public void testCreateNonConfig() throws IOException {
        Path tempFile = Files.createTempFile("sk-", ".tmp");
        new Configuration(tempFile.toAbsolutePath().toString());
    }

    @Test
    public void testCreateGood() {
        Configuration configuration = new Configuration("src/test/resources/blacklist-all.conf");

        assertFalse(configuration.isLogging());
        assertFalse(configuration.isProfiling());
        assertEquals("/tmp/serialkiller.log", configuration.logFile());
        assertEquals(".*", configuration.blacklist().iterator().next().pattern());
        assertEquals("java\\.lang\\..*", configuration.whitelist().iterator().next().pattern());
    }

    @Test
    public void testReload() throws Exception {
        Path tempFile = Files.createTempFile("sk-", ".conf");
        Files.copy(new File("src/test/resources/reload-all-the-time.conf").toPath(), tempFile, REPLACE_EXISTING);

        Configuration configuration = new Configuration(tempFile.toAbsolutePath().toString());

        assertFalse(configuration.isLogging());
        assertFalse(configuration.isProfiling());
        assertEquals("/tmp/serialkiller.log", configuration.logFile());
        assertEquals(".*", configuration.blacklist().iterator().next().pattern());
        assertEquals("java\\.lang\\..*", configuration.whitelist().iterator().next().pattern());

        Thread.sleep(120L);

        Files.copy(new File("src/test/resources/whitelist-all.conf").toPath(), tempFile, REPLACE_EXISTING);

        Thread.sleep(120L); // Wait until a reload happens

        assertFalse(configuration.blacklist().iterator().hasNext());
        assertEquals(".*", configuration.whitelist().iterator().next().pattern());
    }
}