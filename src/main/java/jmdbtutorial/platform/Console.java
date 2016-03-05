package jmdbtutorial.platform;

public class Console {

    public static void printlnf(String format, Object... parameters) {
        System.out.println(String.format(format, parameters));
    }

}
