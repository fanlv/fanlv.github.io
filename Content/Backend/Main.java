import java.util.HashMap;
import java.util.HashSet;
import java.util.Stack;
import java.util.concurrent.TimeUnit;

public class Main {
    void m() {
        System.out.println("m num start\n");
        long count = 1;
        while (running) {
            count++;
        }
        System.out.println("m num end\n");
    }

    /* volatile */ boolean running = true;

    public static void main(String[] args) {
        Main test = new Main();
        new Thread(test::m, "t1").start();

        try {
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        test.running = false;
    }
}