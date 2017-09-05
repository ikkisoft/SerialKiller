package org.nibblesec.tools;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Date;

import org.junit.Test;

/**
 * SerialKillerTest
 */
public class SerialKillerTest {
    @Test
    public void testBlacklisted() throws Exception {
        try (ObjectInputStream stream = new SerialKiller(getClass().getResourceAsStream("/hibernate1.ser"), "config/serialkiller.conf")) {
            try {
                stream.readObject();
                fail();
            } catch (InvalidClassException expected) {
                assertThat(expected.getMessage(), containsString("blocked"));
                assertThat(expected.getMessage(), containsString("blacklist"));
                assertThat(expected.getMessage(), not(containsString("whitelist")));
                assertThat(expected.classname, equalTo("org.hibernate.engine.spi.TypedValue"));
            } catch (ClassNotFoundException e) {
                fail(e.getMessage());
            }
        }
    }

    @Test
    public void testNonWhitelisted() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        try (ObjectOutputStream stream = new ObjectOutputStream(bytes)) {
            stream.writeObject(new java.sql.Date(42L));
        }

        try (ObjectInputStream stream = new SerialKiller(new ByteArrayInputStream(bytes.toByteArray()), "config/serialkiller.conf")) {
            try {
                stream.readObject();
                fail();
            } catch (InvalidClassException expected) {
                assertThat(expected.getMessage(), containsString("blocked"));
                assertThat(expected.getMessage(), containsString("whitelist"));
                assertThat(expected.getMessage(), not(containsString("blacklist")));
                assertThat(expected.classname, equalTo("java.sql.Date"));
            } catch (ClassNotFoundException e) {
                fail(e.getMessage());
            }
        }
    }

    @Test
    public void testWhitelisted() throws Exception {
        String s = "And they all lived happily ever after";

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        try (ObjectOutputStream stream = new ObjectOutputStream(bytes)) {
            stream.writeObject(s);
            stream.writeObject(42);
        }

        try (ObjectInputStream stream = new SerialKiller(new ByteArrayInputStream(bytes.toByteArray()), "config/serialkiller.conf")) {
            assertEquals(s, stream.readObject());
            assertEquals(42, stream.readObject());
        }
    }

    @Test(expected = InvalidClassException.class)
    public void testThreadIssue() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        try (ObjectOutputStream stream = new ObjectOutputStream(bytes)) {
            stream.writeObject(42);
        }

        try (ObjectInputStream stream = new SerialKiller(new ByteArrayInputStream(bytes.toByteArray()), "src/test/resources/blacklist-all.conf")) {
            // Create a dummy SK with different config
            new SerialKiller(new ByteArrayInputStream(bytes.toByteArray()), "src/test/resources/whitelist-all.conf");

            stream.readObject();
            fail("All should be blacklisted");
        }
    }

    @Test
    public void testReload() throws Exception {
        Path tempFile = Files.createTempFile("sk-", ".conf");
        Files.copy(new File("src/test/resources/blacklist-all-refresh-10-ms.conf").toPath(), tempFile, REPLACE_EXISTING);

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        try (ObjectOutputStream stream = new ObjectOutputStream(bytes)) {
            stream.writeObject(42);
        }

        try (ObjectInputStream stream = new SerialKiller(new ByteArrayInputStream(bytes.toByteArray()), tempFile.toAbsolutePath().toString())) {
            Files.copy(new File("src/test/resources/whitelist-all.conf").toPath(), tempFile, REPLACE_EXISTING);
            Files.setLastModifiedTime(tempFile, FileTime.fromMillis(System.currentTimeMillis())); // Commons configuration watches file modified time
            Thread.sleep(12L); // Wait to ensure a reload happens

            assertEquals(42, stream.readObject());
        }
    }
}