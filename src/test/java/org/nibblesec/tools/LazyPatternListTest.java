package org.nibblesec.tools;

import static org.junit.Assert.*;

import java.util.Iterator;
import java.util.regex.Pattern;

import org.junit.Test;
import org.nibblesec.tools.SerialKiller.LazyPatternList;

/**
 * LazyPatternListTest
 */
public class LazyPatternListTest {
    @Test(expected = NullPointerException.class)
    public void testCreateNull() {
        new LazyPatternList(null);
    }

    @Test
    public void testCreateSingle() {
        LazyPatternList list = new LazyPatternList("a");

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
        LazyPatternList list = new LazyPatternList(patterns);

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
        LazyPatternList list = new LazyPatternList(patterns);
        patterns[1] = "three";

        int index = 0;
        for (Pattern pattern : list) {
            assertEquals(String.valueOf(++index), pattern.pattern());
        }

        assertEquals(2, index);
    }
}