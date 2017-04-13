package jmdbtutorial.platform;

import java.net.URL;

import static java.lang.String.format;
import static java.lang.Thread.currentThread;

public class ClassPathResources {
    public static URL getResourceRelativeTo(Object source, String filename) {
        String packageName = source.getClass().getPackage().getName();
        String path = packageName.replaceAll("\\.", "/");

        String fullPath = format("%s/%s", path, filename);
        URL url = currentThread().getContextClassLoader().getResource(fullPath);

        if (url == null) {
            throw new RuntimeException("Could not find resource (don't forget to add src dirs as resources in eg gradle or mvn!): " + fullPath);
        }

        return url;
    }
}
