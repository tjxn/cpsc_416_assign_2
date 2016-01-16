/*
Implements the solution to assignment 1 for UBC CS 416 2015 W2.

Usage:
$ go run client.go [local UDP ip:port] [aserver UDP ip:port] [secret]

Example:
$ go run client.go 127.0.0.1:2020 198.162.52.206:1999

*/

package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"strconv"
	"time"
)

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

/////////// Helper Functions:

func errorCheck(err error, message string) {

	if err != nil {
		fmt.Println(message)
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
}

func openConnection(localAddr, remoteAddr string) *net.UDPConn {

	_, port, err := net.SplitHostPort(localAddr)
	errorCheck(err, "Something is Wrong with the given local address format")

	port = ":" + port

	laddr, err := net.ResolveUDPAddr("udp", port)
	errorCheck(err, "Something is Wrong with the given local address")

	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	errorCheck(err, "Something is Wrong with the given remote address")

	conn, err := net.DialUDP("udp", laddr, raddr)
	errorCheck(err, "Something has gone wrong in the initial connection")

	return conn
}

func sendString(conn *net.UDPConn, message string) {

	buffer := []byte(message)
	_, err := conn.Write(buffer)
	errorCheck(err, "Problem with Sending String: "+message)
}

func sendBytes(conn *net.UDPConn, message []byte) {

	_, err := conn.Write(message)
	errorCheck(err, "Problem with Sending Byte Slice")

}

func readMessage(conn *net.UDPConn) ([]byte, *net.UDPAddr) {

	buffer := make([]byte, 1024)
	fmt.Println("Read from buffer")
	bytesRead, retAddr, err := conn.ReadFromUDP(buffer)
	errorCheck(err, "Problem with Reading UDP Packet")

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

func convertByteSpliceToHexString(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

func parseNonceMessage(segment []byte) NonceMessage {

	nonce := NonceMessage{}
	err := json.Unmarshal(segment, &nonce)
	errorCheck(err, "Error in parsing JSON Nonce Message")

	return nonce
}

func createHashMessage(secret string, nonce NonceMessage) []byte {
	var hashBytes []byte = computeMd5(secret, nonce.Nonce)
	var hashString string = convertByteSpliceToHexString(hashBytes)

	hash := &HashMessage{
		Hash: hashString,
	}

	packet, err := json.Marshal(hash)
	errorCheck(err, "Error in creating JSON Hash Message")

	return packet
}

func parseFortuneInfoMessage(message []byte) FortuneInfoMessage {

	fortuneInfo := FortuneInfoMessage{}

	err := json.Unmarshal(message, &fortuneInfo)
	errorCheck(err, "Error in parsing JSON Fortune Info Message")

	return fortuneInfo

}

func startListening(localAddr string) *net.UDPConn {

	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	errorCheck(err, "Something is Wrong with the given local address")

	conn, err := net.ListenUDP("udp", laddr)
	errorCheck(err, "Something Went Wrong with Listening for UDP Packets")

	return conn
}

func createFortuneReqMessage(nonce int64) []byte {

	fortuneReq := &FortuneReqMessage{
		FortuneNonce: nonce,
	}

	packet, err := json.Marshal(fortuneReq)
	errorCheck(err, "Error in creating Fortune Req Message")

	return packet
}

func parseFortuneMessage(message []byte) FortuneMessage {

	fortune := FortuneMessage{}

	err := json.Unmarshal(message, &fortune)
	errorCheck(err, "Error in parsing JSON Fortune Message")

	return fortune
}

func generateNonce() int64 {
	source := rand.NewSource(time.Now().UnixNano())
	randomGenerator := rand.New(source)

	return randomGenerator.Int63()
}

type FortuneServerRPC struct{}

func (this *FortuneServerRPC) GetFortuneInfo(clientAddr string, fInfoMsg *FortuneInfoMessage) error {
	fInfoMsg.FortuneNonce = generateNonce()
	fInfoMsg.FortuneServer = udpServerAddress

	fmt.Printf("Nonce: %d\n", fInfoMsg.FortuneNonce)

	recordClientNonce(clientAddr, fInfoMsg.FortuneNonce)
	return errors.New("")
}

func recordClientNonce(clientAddr string, nonce int64) {
	clientList[clientAddr] = nonce
	fmt.Printf("New Addition Address: %s\n", clientAddr)
	fmt.Printf("New Addition Nonce: %d\n", clientList[clientAddr])
}

var udpServerAddress string
var clientList map[string]int64

func parseFortuneReqMessage(message []byte) FortuneReqMessage {
	fortuneReq := FortuneReqMessage{}

	err := json.Unmarshal(message, &fortuneReq)
	errorCheck(err, "Error in parsing JSON Fortune Message")

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

func handleRequest(conn *net.UDPConn, message []byte, clientAddr *net.UDPAddr, fortune string) {

	var fortuneReq FortuneReqMessage = parseFortuneReqMessage(message)
	fmt.Printf("client address: %s\n", clientAddr.String())
	fmt.Printf("expected nonce: %d\n", clientList[clientAddr.String()])
	fmt.Printf("given nonce: %d\n", fortuneReq.FortuneNonce)
	if clientList[clientAddr.String()] == fortuneReq.FortuneNonce {
		// send Fortune
		var packet []byte = createFortuneMessage(fortune)
		conn.WriteToUDP(packet, clientAddr)
	} else {
		var packet []byte = createErrorMessage("unexpected hash value")
		// Send ErrMessage
		fmt.Println("Nonce didn't match")
		conn.WriteToUDP(packet, clientAddr)
	}

}

// Main workhorse method.
func main() {

	// Arguments
	//var rpcAddr string = os.Args[1]
	udpServerAddress = os.Args[2]
	var fortune string = os.Args[3]

	// Hardcoded Arguments for Easier Debugging
	//var rpcAddr string = "127.0.0.1:2020"
	//var udpAddr string = "198.162.52.206:1999"
	//var fortune string = "2016"

	clientList = make(map[string]int64)

	rpcFunc := new(FortuneServerRPC)
	rpc.Register(rpcFunc)
	rpc.HandleHTTP()

	go http.ListenAndServe(":1234", nil)
	//errorCheck(err, "listen and serve")

	fmt.Println("starting listening for udp connection")

	var conn *net.UDPConn = startListening(udpServerAddress)

	for {
		message, clientAddr := readMessage(conn)
		fmt.Println("Got a udp packet")
		go handleRequest(conn, message, clientAddr, fortune)
	}

	//	var nonce NonceMessage = parseNonceMessage(message)

	//	var packet []byte = createHashMessage(secret, nonce)

	//	sendBytes(conn, packet)

	//	message = readMessage(conn)

	//	var fortuneinfo FortuneInfoMessage = parseFortuneInfoMessage(message)

	//	conn.Close()

	//	conn = openConnection(localAddr, fortuneinfo.FortuneServer)

	//	packet = createFortuneReqMessage(fortuneinfo.FortuneNonce)

	//	sendBytes(conn, packet)

	//	message = readMessage(conn)

	//	var fortune FortuneMessage = parseFortuneMessage(message)

	//	fmt.Println(fortune.Fortune)

	//	conn.Close()
}
