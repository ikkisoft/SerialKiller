package org.nibblesec.tools;

import org.junit.Test;
import org.nibblesec.tools.util.Person;

import javax.naming.ConfigurationException;
import java.io.*;

public class SerialKillerSpeedTest {

    @Test
    public void speedTest() throws IOException, ConfigurationException, ClassNotFoundException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream outputStream = new ObjectOutputStream(byteArrayOutputStream);
        Person outPerson = new Person(1, "Test");

        outputStream.writeObject(outPerson);
        outputStream.flush();
        outputStream.close();

        speedTest(byteArrayOutputStream, new TestDeserializeCommon(),false);
        speedTest(byteArrayOutputStream, new TestDeserializeSerialKiller(), true);
    }

    private static void speedTest(ByteArrayOutputStream byteArrayOutputStream, TestDeserialize testDeserialize, boolean withSerialKiller) throws IOException, ClassNotFoundException, ConfigurationException {
        for (int i = 0; i < 1000; i++) {
            testDeserialize.deserialize(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
        }

        long timeStart = System.currentTimeMillis();
        for (int i = 0; i < 10_000; i++) {
            testDeserialize.deserialize(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
        }

        long result = System.currentTimeMillis() - timeStart;
        if(withSerialKiller){
            System.out.println("Result (WITH SerialKiller): " + result + "ms for 10.000 iterations");
        }else{
            System.out.println("Result (WITHOUT SerialKiller): " + result + "ms for 10.000 iterations");
        }
    }

    interface TestDeserialize{
        void deserialize(InputStream is) throws IOException, ClassNotFoundException, ConfigurationException;
    }

    class TestDeserializeCommon implements TestDeserialize{
        public void deserialize(InputStream is) throws IOException, ClassNotFoundException {
            ObjectInputStream objectInputStream = new ObjectInputStream(is);
            Person inPerson = (Person) objectInputStream.readObject();
        }
    }

    class TestDeserializeSerialKiller implements TestDeserialize{

        public void deserialize(InputStream is) throws IOException, ClassNotFoundException, ConfigurationException {
            ObjectInputStream ois = new SerialKiller(is, "src/test/resources/serialkiller-speedtest.conf");
            Person inPersonSerial = (Person) ois.readObject();
        }
    }
}
