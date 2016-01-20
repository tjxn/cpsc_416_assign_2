/*
Implements the solution to assignment 2 for UBC CS 416 2015 W2.

Usage:
$ go run auth-server.go [local UDP ip:port] [fserver rpc ip:port] [secret]

Example:
$ go run auth-server.go 192.168.1.146:2020 192.168.1.146:1234 2016

*/

package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
var clientList map[string][]byte

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

func startListening(localAddr string) *net.UDPConn {

	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	errorCheck(err, "Something is Wrong with the given local address")

	conn, err := net.ListenUDP("udp", laddr)
	errorCheck(err, "Something Went Wrong with Listening for UDP Packets")

	return conn
}

func sendBytes(conn *net.UDPConn, message []byte) {

	_, err := conn.Write(message)
	errorCheck(err, "Problem with Sending Byte Slice")

}

func readMessage(conn *net.UDPConn) ([]byte, *net.UDPAddr) {

	buffer := make([]byte, 1024)

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

func createNonceMessage(nonce int64) []byte {
	nonceMessage := &NonceMessage{
		Nonce: nonce,
	}

	packet, err := json.Marshal(&nonceMessage)
	errorCheck(err, "Error in creating Nonce Message")

	return packet
}

func createFortuneInfoMessage(fortuneInfo FortuneInfoMessage) []byte {
	packet, err := json.Marshal(&fortuneInfo)
	errorCheck(err, "Error in creating FortuneInfoMessage")

	return packet
}

func createErrorMessage(message string) []byte {
	errorMessage := &ErrMessage{
		Error: message,
	}

	packet, err := json.Marshal(&errorMessage)
	errorCheck(err, "Error in creating Error Message")

	return packet
}

// Return true if byte slice was a HashMessage
// Always return HashMessage, even if empty
func parseHashMessage(message []byte) (bool, HashMessage) {

	hashMessage := HashMessage{}

	err := json.Unmarshal(message, &hashMessage)

	if err != nil {
		return false, hashMessage
	} else {
		return true, hashMessage
	}
}

func recordClientHash(clientAddr *net.UDPAddr, hash []byte, clientList map[string][]byte) {
	clientList[clientAddr.String()] = hash
}

func generateNonce() int64 {
	source := rand.NewSource(time.Now().UnixNano())
	randomGenerator := rand.New(source)

	return randomGenerator.Int63()
}

func getClientHash(clientAddr *net.UDPAddr, clientList map[string][]byte) []byte {
	return clientList[clientAddr.String()]
}

func checkHashMatch(expectedHash []byte, givenHash string) bool {
	var expHash string = convertByteSpliceToHexString(expectedHash)

	if expHash == givenHash {
		return true
	} else {
		return false
	}
}

// Main workhorse method
// Handles any incoming packet
func handleRequest(conn *net.UDPConn, localAddr string, remoteAddr string, secret string, message []byte, clientAddr *net.UDPAddr) {

	// Returns true if message is a valid HashMessage
	check, hashMessage := parseHashMessage(message)

	if check {

		// Check that client has been given a nonce
		hash := getClientHash(clientAddr, clientList)

		if len(hash) <= 0 {

			// Create and Send Error Message
			var packet []byte = createErrorMessage("unknown remote client address")
			conn.WriteToUDP(packet, clientAddr)
			runtime.Goexit()
		}

		// Check that hash from packet matches one we expected
		var match bool = checkHashMatch(hash, hashMessage.Hash)

		if !match {

			// Create and Send Error Message
			var packet []byte = createErrorMessage("unexpected hash value")
			conn.WriteToUDP(packet, clientAddr)
			runtime.Goexit()
		}

		// get Fortune Server Info
		client, _ := rpc.Dial("tcp", remoteAddr)
		fortuneInfo := FortuneInfoMessage{}

		err := client.Call("FortuneServerRPC.GetFortuneInfo", clientAddr.String(), &fortuneInfo)
		errorCheck(err, "rcp call")

		// send FortuneInfoMessage
		var packet []byte = createFortuneInfoMessage(fortuneInfo)
		conn.WriteToUDP(packet, clientAddr)

	} else {
		// Send a new Nonce to the client
		var nonce int64 = generateNonce()

		hash := computeMd5(secret, nonce)
		recordClientHash(clientAddr, hash, clientList)
		var packet = createNonceMessage(nonce)

		conn.WriteToUDP(packet, clientAddr)
	}

}

func main() {

	// Arguments
	//var localAddr string = os.Args[1]
	//var remoteAddr string = os.Args[2]
	//var secret string = os.Args[3]

	// Hardcoded Arguments for Easier Debugging
	var localAddr string = "192.168.1.146:2020"
	var remoteAddr string = "192.168.1.146:1234"
	var secret string = "2016"

	// Keeps track of clients who have connected
	// Key: Client *net.UDPAddr address in string format
	// Value: Nonce as a byte slice
	clientList = make(map[string][]byte)

	var conn *net.UDPConn = startListening(localAddr)

	// Read every incoming packet and hand the packet off to a new goroutine
	for {
		message, clientAddr := readMessage(conn)
		go handleRequest(conn, localAddr, remoteAddr, secret, message, clientAddr)
	}

}
