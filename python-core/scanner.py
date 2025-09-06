import java.net.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 Java CLI Scanner Ready");
        try {
            InetAddress ip = InetAddress.getByName("example.com");
            System.out.println("✅ Host IP: " + ip.getHostAddress());
        } catch (Exception e) {
            System.out.println("❌ Error resolving host");
        }
    }
}
