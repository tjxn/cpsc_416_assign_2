/*
Implements the solution to assignment 2 for UBC CS 416 2015 W2.

Usage:
$ go run fortune-server.go [Local rpc ip:port] [Local UDP ip:port] [fortune-string]

Example:
$ go run fortune-server.go 192.168.1.146:1234 192.168.1.146:3000 "Hello World"

*/

package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/rpc"
	"os"
	"runtime"
	"strconv"
	"time"
)

/////// Global Variables
var udpServerAddress string
var clientList map[string]int64

/////////// Msgs used by both auth and fortune servers:

// An error message from the server.
type ErrMessage struct {
	Error string
}

/////////// Auth server msgs:

// Message containing a nonce from auth-server.
type NonceMessage struct {
	Nonce int64
}

// Message containing an MD5 hash from client to auth-server.
type HashMessage struct {
	Hash string
}

// Message with details for contacting the fortune-server.
type FortuneInfoMessage struct {
	FortuneServer string
	FortuneNonce  int64
}

/////////// Fortune server msgs:

// Message requesting a fortune from the fortune-server.
type FortuneReqMessage struct {
	FortuneNonce int64
}

// Response from the fortune-server containing the fortune.
type FortuneMessage struct {
	Fortune string
}

// Used for RPC
type FortuneServerRPC struct{}

/////////// Helper Functions:

func errorCheck(err error, message string) {

	if err != nil {
		fmt.Println(message)
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
}

func readMessage(conn *net.UDPConn) ([]byte, *net.UDPAddr) {

	buffer := make([]byte, 1024)

	bytesRead, retAddr, err := conn.ReadFromUDP(buffer)
	errorCheck(err, "Error Reading UDP Packet")

	buffer = buffer[:bytesRead]

	return buffer, retAddr
}

func convertStringToInt64(toConvert string) int64 {

	converted, err := strconv.ParseInt(toConvert, 10, 64)
	errorCheck(err, "Problem with the given Secret: "+toConvert)

	return converted
}

func convertInt64ToByteSlice(num int64) []byte {
	buf := make([]byte, 64)

	bytesRead := binary.PutVarint(buf, num)
	hashByte := buf[:bytesRead]

	return hashByte
}

func computeMd5(secret string, nounce int64) []byte {
	var secretNum int64 = convertStringToInt64(secret)

	var toHash int64 = secretNum + nounce

	var hashByte []byte = convertInt64ToByteSlice(toHash)

	hasher := md5.New()
	hasher.Write(hashByte)
	hash := hasher.Sum(nil)

	return hash
}

func startListening(localAddr string) *net.UDPConn {

	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	errorCheck(err, "Something is Wrong with the given local address")

	conn, err := net.ListenUDP("udp", laddr)
	errorCheck(err, "Something Went Wrong with Listening for UDP Packets")

	return conn
}

func generateNonce() int64 {
	source := rand.NewSource(time.Now().UnixNano())
	randomGenerator := rand.New(source)

	return randomGenerator.Int63()
}

func (this *FortuneServerRPC) GetFortuneInfo(clientAddr string, fInfoMsg *FortuneInfoMessage) error {
	fInfoMsg.FortuneNonce = generateNonce()
	fInfoMsg.FortuneServer = udpServerAddress

	recordClientNonce(clientAddr, fInfoMsg.FortuneNonce)
	return errors.New("")
}

func recordClientNonce(clientAddr string, nonce int64) {
	clientList[clientAddr] = nonce
}

func parseFortuneReqMessage(message []byte, clientAddr *net.UDPAddr, conn *net.UDPConn) FortuneReqMessage {
	fortuneReq := FortuneReqMessage{}

	err := json.Unmarshal(message, &fortuneReq)

	if err != nil || fortuneReq.FortuneNonce == 0 {
		var packet = createErrorMessage("could not interpret message")
		conn.WriteToUDP(packet, clientAddr)
		runtime.Goexit()
	}

	return fortuneReq
}

func createErrorMessage(message string) []byte {
	errorMessage := &ErrMessage{
		Error: message,
	}

	packet, err := json.Marshal(&errorMessage)
	errorCheck(err, "Error in creating Error Message")

	return packet
}

func createFortuneMessage(fortune string) []byte {

	fortuneMes := &FortuneMessage{
		Fortune: fortune,
	}

	packet, err := json.Marshal(fortuneMes)
	errorCheck(err, "Error in creating Fortune Message")

	return packet
}

// Main workhorse method.
// Handles any incoming packet
func handleRequest(conn *net.UDPConn, message []byte, clientAddr *net.UDPAddr, fortune string) {

	var fortuneReq FortuneReqMessage = parseFortuneReqMessage(message, clientAddr, conn)

	// Check if Fortune Nonce given matches one received
	if clientList[clientAddr.String()] == fortuneReq.FortuneNonce {
		var packet []byte = createFortuneMessage(fortune)
		conn.WriteToUDP(packet, clientAddr)
	}

	// Check if Client Address has never been seen before
	if clientList[clientAddr.String()] == 0 {
		var packet []byte = createErrorMessage("unknown remote client address")
		conn.WriteToUDP(packet, clientAddr)

	} else {
		var packet []byte = createErrorMessage("incorrect fortune nonce")
		conn.WriteToUDP(packet, clientAddr)
	}

}

func startRPC(rpcAddr string) {
	rpcFunc := new(FortuneServerRPC)
	rpc.Register(rpcFunc)

	addr, err := net.ResolveTCPAddr("tcp", rpcAddr)
	errorCheck(err, "Problem Resolving given rpc Address")

	inbound, err := net.ListenTCP("tcp", addr)
	errorCheck(err, "Problem listening for rcp calls")

	go listenAndServe(inbound)
}

func listenAndServe(listener net.Listener) {
	for {
		rpc.Accept(listener)
	}
}

func main() {

	// Arguments
	var rpcAddr string = os.Args[1]
	udpServerAddress = os.Args[2]
	var fortune string = os.Args[3]

	// Hardcoded Arguments for Easier Debugging
	//var rpcAddr string = "192.168.1.146:1234"
	//udpServerAddress = "192.168.1.146:3000"
	//var fortune string = "Hello World - Trevor Jackson"

	// Keeps track of clients who have connected to aserver
	// Key: Client *net.UDPAddr address in string format
	// Value: Nonce as a int64
	clientList = make(map[string]int64)

	startRPC(rpcAddr)

	var conn *net.UDPConn = startListening(udpServerAddress)

	// Read every incoming packet and hand the packet off to a new goroutine
	for {
		message, clientAddr := readMessage(conn)
		go handleRequest(conn, message, clientAddr, fortune)
	}
}
