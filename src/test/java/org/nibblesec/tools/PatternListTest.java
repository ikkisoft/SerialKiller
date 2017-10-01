package org.nibblesec.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.junit.Test;
import org.nibblesec.tools.SerialKiller.TemplateList;

/**
 * PatternListTest
 */
public class PatternListTest {
    @Test(expected = NullPointerException.class)
    public void testCreateNull() {
        new TemplateList(null,(String[]) null);
    }

    @Test(expected = PatternSyntaxException.class)
    public void testCreateBadPattern() {
        new TemplateList(null,"(");
    }

    @Test
    public void testCreateEmpty() {
        TemplateList list = new TemplateList(null);

        Iterator<Pattern> iterator = list.iterator();
        assertFalse(iterator.hasNext());
    }

    @Test
    public void testCreateSingle() {
        TemplateList list = new TemplateList(null,"a");

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
        TemplateList list = new TemplateList(null, patterns);

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
        TemplateList list = new TemplateList(null,patterns);
        patterns[1] = "three";

        int index = 0;
        for (Pattern pattern : list) {
            assertEquals(String.valueOf(++index), pattern.pattern());
        }

        assertEquals(2, index);
    }
}