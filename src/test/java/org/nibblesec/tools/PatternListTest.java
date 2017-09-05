package org.nibblesec.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.junit.Test;
import org.nibblesec.tools.SerialKiller.PatternList;

/**
 * PatternListTest
 */
public class PatternListTest {
    @Test(expected = NullPointerException.class)
    public void testCreateNull() {
        new PatternList((String[]) null);
    }

    @Test(expected = PatternSyntaxException.class)
    public void testCreateBadPattern() {
        new PatternList("(");
    }

    @Test
    public void testCreateEmpty() {
        PatternList list = new PatternList();

        Iterator<Pattern> iterator = list.iterator();
        assertFalse(iterator.hasNext());
    }

    @Test
    public void testCreateSingle() {
        PatternList list = new PatternList("a");

        Iterator<Pattern> iterator = list.iterator();
        assertTrue(iterator.hasNext());
        Pattern pattern = iterator.next();
        assertNotNull(pattern);
        assertEquals("a", pattern.pattern());
        assertFalse(iterator.hasNext());
    }

    @Test
    public void testCreateSequence() {
        String[] patterns = {"a", "b", "c"};
        PatternList list = new PatternList(patterns);

        int index = 0;
        for (Pattern pattern : list) {
            assertNotNull(pattern);
            assertEquals(patterns[index++], pattern.pattern());
        }

        assertEquals(3, index);
    }

    @Test
    public void testCreateSafeArgs() {
        String[] patterns = {"1", "2"};
        PatternList list = new PatternList(patterns);
        patterns[1] = "three";

        int index = 0;
        for (Pattern pattern : list) {
            assertEquals(String.valueOf(++index), pattern.pattern());
        }

        assertEquals(2, index);
    }
}