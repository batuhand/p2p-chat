/*
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Juan Batiz-Benet
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * This program demonstrate a simple chat application using p2p communication.
 *
 */
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/libp2p/go-libp2p"
	"github.com/multiformats/go-multiaddr"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

var ID string

func handleStream(s network.Stream) {
	log.Println("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	go readData(rw)
	go writeData(rw)

	// stream 's' will stay open until you close it (or the other side closes it).
}

func readData(rw *bufio.ReadWriter) {
	for {
		str, _ := rw.ReadString('\n')

		if str == "" {
			return
		}
		if str != "\n" {
			// Green console colour: 	\x1b[32m
			// Reset console colour: 	\x1b[0m
			fmt.Printf("\x1b[32m%s\x1b[0m> ", str)
		}

	}
}

func writeData(rw *bufio.ReadWriter) {
	stdReader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		sendData, err := stdReader.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}

		rw.WriteString(fmt.Sprintf("%s\n", sendData))
		rw.Flush()
	}
}
func localAddresses() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
			continue
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPAddr:
				fmt.Printf("%v : %s (%s)\n", i.Name, v, v.IP.DefaultMask())

			case *net.IPNet:
				fmt.Printf("%v : %s [%v/%v]\n", i.Name, v, v.IP, v.Mask)
			}

		}
	}
}

func GetHostId(req string) Creds {
	client := http.Client{
		Timeout: 200 * time.Millisecond,
	}
	resp, err := client.Get(req + "/get_creds")
	if err != nil {
		fmt.Println(err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var R Response
			R.Data = Creds{}
			jsonDataFromHttp, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				panic(err)
			}
			err = json.Unmarshal(jsonDataFromHttp, &R) // here!
			if err != nil {
				panic(err)
			}
			return R.Data

		}
	}
	return Creds{}
}

func GetAddresses() {
	cmd := "cat ifconfig | grep broadcast"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Sprintf("Failed to execute command: %s", cmd)
	}
	fmt.Println(string(out))
}

func RunWithArgs() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sourcePort := flag.Int("sp", 0, "Source port number")
	dest := flag.String("d", "", "Destination multiaddr string")
	help := flag.Bool("help", false, "Display help")
	debug := flag.Bool("debug", false, "Debug generates the same node ID on every execution")

	flag.Parse()

	if *help {
		fmt.Printf("This program demonstrates a simple p2p chat application using libp2p\n\n")
		fmt.Println("Usage: Run './chat -sp <SOURCE_PORT>' where <SOURCE_PORT> can be any port number.")
		fmt.Println("Now run './chat -d <MULTIADDR>' where <MULTIADDR> is multiaddress of previous listener host.")

		os.Exit(0)
	}

	// If debug is enabled, use a constant random source to generate the peer ID. Only useful for debugging,
	// off by default. Otherwise, it uses rand.Reader.
	var r io.Reader
	if *debug {
		// Use the port number as the randomness source.
		// This will always generate the same host ID on multiple executions, if the same port number is used.
		// Never do this in production code.
		r = mrand.New(mrand.NewSource(int64(*sourcePort)))
	} else {
		r = rand.Reader
	}

	h, err := makeHost(*sourcePort, r)
	if err != nil {
		log.Println(err)
		return
	}

	if *dest == "" {
		startPeer(ctx, h, handleStream)
	} else {
		rw, err := startPeerAndConnect(ctx, h, *dest)
		if err != nil {
			log.Println(err)
			return
		}

		// Create a thread to read and write data.
		go writeData(rw)
		go readData(rw)

	}

	// Wait forever
	select {}
}

func GetAvailableAddresses() []string {
	fmt.Println("Seacrhing for available hosts... Please wait....")
	var addList []string
	for i := 1; i < 256; i++ {
		req := fmt.Sprintf("http://192.168.0.%d:3001/hc", i)
		client := http.Client{
			Timeout: 20 * time.Millisecond,
		}
		resp, err := client.Get(req)
		if err != nil {
			continue
		} else {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				addList = append(addList, fmt.Sprintf("http://192.168.0.%d:3001", i))
				continue
			}
		}
	}
	return addList
}

func RunWithoutArgs() {

	fmt.Println("Sa\n1-Create session\n2-Join session")
	choice := 0
	port := 8080
	fmt.Scanln(&choice)

	switch choice {
	case 1:
		Start()
		ctx, cancel := context.WithCancel(context.Background())
		var r io.Reader
		r = rand.Reader
		fmt.Println("Please enter Port")
		fmt.Scanln(&port)
		h, err := makeHost(port, r)
		defer cancel()

		if err != nil {
			log.Println(err)
			return
		}
		startPeer(ctx, h, handleStream)
		select {}
	case 2:
		addressList := GetAvailableAddresses()
		for index, address := range addressList {
			fmt.Println(fmt.Sprintf("%d- %s", index+1, address))
		}

		var r io.Reader
		r = rand.Reader
		h, err := makeHost(port+1, r)
		selectedAddress := 0
		fmt.Scanln(&selectedAddress)
		fmt.Println("Selected address: ", addressList[selectedAddress-1])
		hostCreds := GetHostId(addressList[selectedAddress-1])
		dest := fmt.Sprintf("/ip4/%s/tcp/8080/p2p/%s", hostCreds.Ip, hostCreds.Key)
		fmt.Println(dest, "-----------")
		rw, err := startPeerAndConnect(nil, h, dest)
		if err != nil {
			log.Println(err)
			return
		}
		// Create a thread to read and write data.
		go writeData(rw)
		go readData(rw)

		// Wait forever
		select {}
	}
}

func GetIpv4() string {
	host, _ := os.Hostname()
	addrs, _ := net.LookupIP(host)
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			fmt.Println("IPv4: ", ipv4)
			if ipv4.String() != "127.0.0.1" {
				return ipv4.String()

			}
		}
	}
	return ""
}
func main() {
	argsWithoutProg := os.Args[1:]

	if len(argsWithoutProg) < 1 {
		RunWithoutArgs()
		//GetAddresses()
	} else {
		RunWithArgs()
	}

}
func GetNetMask(deviceName string) string {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("ipconfig", "getoption", deviceName, "subnet_mask")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return ""
		}

		nm := strings.Replace(string(out), "\n", "", -1)
		log.Println("netmask=", nm, " OS=", runtime.GOOS)
		return nm
	default:
		return ""
	}
	return ""
}
func makeHost(port int, randomness io.Reader) (host.Host, error) {
	// Creates a new RSA key pair for this host.
	prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, randomness)

	if err != nil {
		log.Println(err)
		return nil, err
	}

	// 0.0.0.0 will listen on any interface device.
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port))

	// libp2p.New constructs a new libp2p Host.
	// Other options can be added here.
	return libp2p.New(
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(prvKey),
	)
}

func startPeer(ctx context.Context, h host.Host, streamHandler network.StreamHandler) {
	// Set a function as stream handler.
	// This function is called when a peer connects, and starts a stream with this protocol.
	// Only applies on the receiving side.
	h.SetStreamHandler("/chat/1.0.0", streamHandler)

	// Let's get the actual TCP port from our listen multiaddr, in case we're using 0 (default; random available port).
	var port string
	for _, la := range h.Network().ListenAddresses() {
		if p, err := la.ValueForProtocol(multiaddr.P_TCP); err == nil {
			port = p
			break
		}
	}

	if port == "" {
		log.Println("was not able to find actual local port")
		return
	}
	ID = h.ID().Pretty()
	log.Printf("Run './chat -d /ip4/127.0.0.1/tcp/%v/p2p/%s' on another console.\n", port, h.ID().Pretty())
	log.Println("You can replace 127.0.0.1 with public IP as well.")
	log.Println("Waiting for incoming connection")
	log.Println()
}

func startPeerAndConnect(ctx context.Context, h host.Host, destination string) (*bufio.ReadWriter, error) {
	log.Println("This node's multiaddresses:")
	for _, la := range h.Addrs() {
		log.Printf(" - %v\n", la)
	}
	log.Println()

	// Turn the destination into a multiaddr.
	maddr, err := multiaddr.NewMultiaddr(destination)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Extract the peer ID from the multiaddr.
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Add the destination's peer multiaddress in the peerstore.
	// This will be used during connection and stream creation by libp2p.
	h.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	// Start a stream with the destination.
	// Multiaddress of the destination peer is fetched from the peerstore using 'peerId'.
	s, err := h.NewStream(context.Background(), info.ID, "/chat/1.0.0")
	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Println("Established connection to destination")

	// Create a buffered stream so that read and writes are non blocking.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	return rw, nil
}

type Response struct {
	Error string `json:"error"`
	Data  Creds  `json:"data"`
}

func GetCreds(c *fiber.Ctx) error {
	ip := GetIpv4()
	if ip == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(Response{Error: "something went wrong"})
	}
	var creds Creds
	creds.Ip = ip
	creds.Key = ID
	return c.Status(fiber.StatusOK).JSON(Response{Data: creds})

}

func startServer() {

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	app.Get("/get_creds", GetCreds)
	app.Get("/hc", HealthCheck)
	error := app.Listen(":3001")
	if error != nil {
		fmt.Println(error)
		os.Exit(1)
	}
}
func Start() error {
	// Start should not block. Do the actual work async.
	go run()
	return nil
}
func run() {
	startServer()

}

func HealthCheck(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON("ME ALIVE CYKA")
}

type Creds struct {
	Ip  string `json:"ip"`
	Key string `json:"key"`
}
