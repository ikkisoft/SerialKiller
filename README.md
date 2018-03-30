# SerialKiller ![SerialKiller Logo](https://ikkisoft.com/img/sk.png "SerialKiller Logo")

**SerialKiller** is an easy-to-use look-ahead Java deserialization library to secure application from untrusted input.

When Java serialization is used to exchange information between a client and a server, attackers can replace the legitimate serialized stream with malicious data. Inspired by this [article](http://www.ibm.com/developerworks/library/se-lookahead/), SerialKiller inspects Java classes during naming resolution and allows a combination of blacklisting/whitelisting to secure your application.

![SerialKiller in action](http://i.imgur.com/wgoF62D.png "SerialKiller in action")

> **Disclaimer:** 
> This library may (or may not) be 100% production ready yet. Use at your own risk!

### How to protect your application with SerialKiller
1. Download the latest version of the [SerialKiller's Jar](https://github.com/ikkisoft/SerialKiller/releases/). Alternatively, this library is also available on [Maven Central](http://search.maven.org/#search%7Cga%7C1%7Cserialkiller)
2. Import SerialKiller's Jar in your project
3. Replace your deserialization *ObjectInputStream* with SerialKiller
4. Tune the configuration file, based on your application requirements

Easy, isn't it? Let's look at a few details...

### Changes required in your code (step 3)
In your original code, you'll probably have something similar to:

```java
ObjectInputStream ois = new ObjectInputStream(is);
String msg = (String) ois.readObject();
```

In order to detect malicious payloads or allow your application's classes only, we need to use SerialKiller instead of the standard *java.io.ObjectInputStream*. This can be done with a one-line change:

```java
ObjectInputStream ois = new SerialKiller(is, "/etc/serialkiller.conf");
String msg = (String) ois.readObject();
```

The second argument is the location of SerialKiller's configuration file.

Finally, you may want to catch *InvalidClassException* exceptions to gracefully handle insecure object deserializations. 
Please note that this library does require *Java 8*.

### Tuning SerialKiller's configuration file (step 4)
SerialKiller config supports the following settings:

 - **Refresh**: The refresh delay in milliseconds, used to *hot-reload* the configuration file. Good news! You don't need to restart your application if you change the config file
 - **BlackList**: A [Java regex](http://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html) to define malicious classes. The [default configuration file](https://github.com/ikkisoft/SerialKiller/blob/master/config/serialkiller.conf) already includes several known payloads so that your application is protected by default against known attacks
 - **WhiteList**: A [Java regex](http://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html) to define classes used by your application. If you can quickly identify a list of trusted classes, this is the best way to secure your application. For instance, you could allow classes in your own package only
 - **Profiling**: Starting from v0.4, SerialKiller introduces a *profiling* mode to enumerate classes deserialized by the application. In this mode, the deserialization is not blocked. To protect your application, make sure to use *'false'* for this setting in production (default value)
 - **Logging**: Logging support compatible to native LogManager using the *java.util.logging.config.file* system property or *lib/logging.properties*. See [Java8 LogManager](https://docs.oracle.com/javase/8/docs/api/java/util/logging/LogManager.html) for more details.

Example of *serialkiller.conf*

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- serialkiller.conf -->
<config>
  <refresh>6000</refresh>
  <mode>
    <!-- set to 'false' for blocking mode -->
    <profiling>false</profiling>
  </mode>
  <blacklist>
  <!--Section for Regular Expressions-->
    <regexps>
        <!-- ysoserial's BeanShell1 payload  -->
        <regexp>bsh\.XThis$</regexp>
        <regexp>bsh\.Interpreter$</regexp>
        <!-- ysoserial's C3P0 payload  -->
        <regexp>com\.mchange\.v2\.c3p0\.impl\.PoolBackedDataSourceBase$</regexp>
	    <!-- ysoserial's MozillaRhino1 payload -->
	    <regexp>org\.mozilla\.javascript\..*$</regexp>
        [...]
    </regexps>
    <!--Section for full-package name-->
    <list>
        <!-- ysoserial's CommonsCollections1,3,5,6 payload  -->
        <name>org.apache.commons.collections.functors.InstantiateTransformer</name>
        <name>org.apache.commons.collections.functors.ConstantTransformer</name>
        <name>org.apache.commons.collections.functors.ChainedTransformer</name>
        <name>org.apache.commons.collections.functors.InvokerTransformer</name>
        [...]
    </list>
  </blacklist>
  <whitelist>
    <regexps>
        <regexp>.*</regexp>
    </regexps>
  </whitelist>
</config>

```

### Credits
 - Ironically, SerialKiller uses some [Apache Commons](https://commons.apache.org/) libraries (configuration, logging, lang, collections)
 - Thanks to [@frohoff](https://twitter.com/frohoff) and [@gebl](https://twitter.com/gebl) for their work on unsafe Java object deserialization payloads. [Ysoserial](https://github.com/frohoff/ysoserial) is awesome!
 - [Pierre Ernst](http://www.ibm.com/developerworks/library/se-lookahead/#authorN10032) for the original idea around look-ahead java deserialization filters

### License
This library has been dual-licensed to Apache License, Version 2.0 and GNU General Public License.

### Contributing
 - If you've discovered a bug, please open an [issue in Github](https://github.com/ikkisoft/SerialKiller/issues).
 - Submit a new RB, especially if you're aware of Java gadgets that can be abused by vulnerable applications. Providing a safe default configuration is extremely useful for less security-oriented users. 
