package org.nibblesec.tools.util;

import java.io.Serializable;

public class Person implements Serializable {

    private int id;
    private String name;

    public Person(int id, String name) {
        this.id = id;
        this.name = name;
    }
}