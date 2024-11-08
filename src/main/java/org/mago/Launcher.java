package org.mago;

import javafx.application.Application;
import java.io.PrintStream;

public class Launcher {
    public static void main(String[] args) {
         PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;

         PrintStream nullStream = new PrintStream(new java.io.OutputStream() {
            @Override
            public void write(int b) {

             }
        });

         System.setOut(nullStream);
        System.setErr(nullStream);

         Application.launch(Main.class, args);

         System.setOut(originalOut);
        System.setErr(originalErr);
    }
}
