package main
import (
    "fmt"
    "net"
    "time"
)

func main() {
    host := "scanme.nmap.org"
    ports := []int{21,22,25,53,80,110,143,443,3306,8080}
    for _, port := range ports {
        address := fmt.Sprintf("%s:%d", host, port)
        conn, err := net.DialTimeout("tcp", address, 2*time.Second)
        if err != nil {
            fmt.Printf("🔴 Port %d closed\n", port)
        } else {
            fmt.Printf("🟢 Port %d open\n", port)
            conn.Close()
        }
    }
}
