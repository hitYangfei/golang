package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
)

const (
	SHA256_DIGEST_LENGTH = 32
	HANDSHAKE_SIZE       = 1536
)

var (
	GENUINE_FMS_KEY = []byte{
		0x47, 0x65, 0x6e, 0x75, 0x69, 0x6e, 0x65, 0x20,
		0x41, 0x64, 0x6f, 0x62, 0x65, 0x20, 0x46, 0x6c,
		0x61, 0x73, 0x68, 0x20, 0x4d, 0x65, 0x64, 0x69,
		0x61, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
		0x20, 0x30, 0x30, 0x31, // Genuine Adobe Flash Media Server 001
		0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8,
		0x2e, 0x00, 0xd0, 0xd1, 0x02, 0x9e, 0x7e, 0x57,
		0x6e, 0xec, 0x5d, 0x2d, 0x29, 0x80, 0x6f, 0xab,
		0x93, 0xb8, 0xe6, 0x36, 0xcf, 0xeb, 0x31, 0xae,
	}
	GENUINE_FP_KEY = []byte{
		0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E, 0x65, 0x20,
		0x41, 0x64, 0x6F, 0x62, 0x65, 0x20, 0x46, 0x6C,
		0x61, 0x73, 0x68, 0x20, 0x50, 0x6C, 0x61, 0x79,
		0x65, 0x72, 0x20, 0x30, 0x30, 0x31,
		0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8,
		0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E, 0x7E, 0x57,
		0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
		0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE,
	}

	//FLASH_PLAYER_VERSION = []byte{0x0A, 0x00, 0x2D, 0x02}
	FLASH_PLAYER_VERSION = []byte{0x09, 0x00, 0x7C, 0x02}
	//FLASH_PLAYER_VERSION = []byte{0x80, 0x00, 0x07, 0x02}
	//FLASH_PLAYER_VERSION_STRING ="LNX 10,0,32,18"
	FLASH_PLAYER_VERSION_STRING = "LNX 9,0,124,2"
	//FLASH_PLAYER_VERSION_STRING ="WIN 11,5,502,146"
	SWF_URL_STRING     = "http://localhost/1.swf"
	PAGE_URL_STRING    = "http://localhost/1.html"
	FMS_VERSION        = []byte{0x04, 0x05, 0x00, 0x01}
	FMS_VERSION_STRING = "4,5,0,297"
)

func main() {
	//建立socket，监听端口
	netListen, err := net.Listen("tcp", "localhost:1935")
	CheckError(err)
	defer netListen.Close()

	Log("Waiting for clients")
	for {
		conn, err := netListen.Accept()
		if err != nil {
			continue
		}

		Log(conn.RemoteAddr().String(), " tcp connect success")
		handleConnection(conn)
	}
}

//处理连接
func handleConnection(conn net.Conn) {
	buffer := make([]byte, HANDSHAKE_SIZE+1)
	status := 0
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			Log(conn.RemoteAddr().String(), " connection error: ", err)
			return
		}
		Log(conn.RemoteAddr().String(), "receive data string length:\n", n)
		//Log(conn.RemoteAddr().String(), "receive data string:\n", string(buffer[:n]))
		if status == 0 {
			if buffer[0] != 0x3 {
				Log("client version is not 0x03")
				return
			} else {
				Log("client version is 0x03")
			}
			input := make([]byte, HANDSHAKE_SIZE)
			copy(input, buffer[1:])
			ver := input[4] & 0xff
			if ver == 0 {
				Log("simple handshake begin")
				//return simple_handshake(rw, input)
			}
			Log("complex handshake begin")
			//return complex_handshake(rw, input)
			result, scheme, challenge, digest := validateClient(input)
			Log("Validate Client %v scheme %v challenge %0X digest %0X", result, scheme, challenge, digest)
			if !result {
				Log(result)
				return
			}
			s1 := create_s1()
			off := getDigestOffset(s1, scheme)
			buf := new(bytes.Buffer)
			buf.Write(s1[:off])
			buf.Write(s1[off+32:])
			tempHash, _ := HMACsha256(buf.Bytes(), GENUINE_FMS_KEY[:36])
			copy(s1[off:], tempHash)
			//compute the challenge digest
			tempHash, _ = HMACsha256(digest, GENUINE_FMS_KEY[:68])
			randBytes := create_s2()
			lastHash, _ := HMACsha256(randBytes, tempHash)
			buf = new(bytes.Buffer)
			buf.WriteByte(0x03)
			buf.Write(s1)
			buf.Write(randBytes)
			buf.Write(lastHash)
			Log("send s0s1s2", buf.Len())
			Log("s1:", s1[0:128])
			conn.Write(buf.Bytes())
			status++
		}
		if status == 1 {
			Log("receiver c2 data,length:", n)
			Log("c2:", buffer[0:128])
		}
	}
}
func getDigestOffset(pBuffer []byte, scheme int) int {
	if scheme == 1 {
		return getDigestOffset1(pBuffer)
	} else if scheme == 0 {
		return getDigestOffset0(pBuffer)
	}
	return -1
}
func Log(v ...interface{}) {
	log.Println(v...)
}

func CheckError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
func HMACsha256(msgBytes []byte, key []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	_, err := h.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
func validateClient(input []byte) (result bool, scheme int, challenge []byte, digest []byte) {
	if result, scheme, challenge, digest = validateClientScheme(input, 0); result {
		Log("scheme 0")
		return
	}
	if result, scheme, challenge, digest = validateClientScheme(input, 1); result {
		Log("scheme 1")
		return
	}
	return
}
func validateClientScheme(pBuffer []byte, scheme int) (result bool, schem int, challenge []byte, digest []byte) {
	digest_offset := -1
	challenge_offset := -1
	if scheme == 0 {
		digest_offset = getDigestOffset0(pBuffer)
		challenge_offset = getDHOffset0(pBuffer)
	} else if scheme == 1 {
		digest_offset = getDigestOffset1(pBuffer)
		challenge_offset = getDHOffset1(pBuffer)
	}
	p1 := pBuffer[:digest_offset]
	digest = pBuffer[digest_offset : digest_offset+32]
	p2 := pBuffer[digest_offset+32:]
	buf := new(bytes.Buffer)
	buf.Write(p1)
	buf.Write(p2)
	p := buf.Bytes()
	//Logf("Scheme: {%v} client digest offset: {%v}", scheme, digest_offset)
	tempHash, _ := HMACsha256(p, GENUINE_FP_KEY[:30])
	//Logf("Temp: {%0X}", tempHash)
	//Logf("Dig : {%0X}", digest)
	result = bytes.Compare(digest, tempHash) == 0
	challenge = pBuffer[challenge_offset : challenge_offset+128]
	schem = scheme
	return
}

/**
 * Returns a digest byte offset.
 *
 * @param pBuffer source for digest data
 * @return digest offset
 */
func getDigestOffset0(pBuffer []byte) int {
	offset := int(pBuffer[8]&0xff) + int(pBuffer[9]&0xff) + int(pBuffer[10]&0xff) + int(pBuffer[11]&0xff)
	Log("the digest offset ", offset)
	offset = (offset % 728) + 8 + 4
	if offset+32 >= 1536 {
		Log("Invalid digest offset")
	}
	return offset
}

/**
 * Returns a digest byte offset.
 *
 * @param pBuffer source for digest data
 * @return digest offset
 */
func getDigestOffset1(pBuffer []byte) int {
	offset := int(pBuffer[772]&0xff) + int(pBuffer[773]&0xff) + int(pBuffer[774]&0xff) + int(pBuffer[775]&0xff)
	offset = (offset % 728) + 772 + 4
	if offset+32 >= 1536 {
		Log("Invalid digest offset")
	}
	Log("digest offset", offset)
	return offset
}

func getDHOffset(handshakeBytes []byte, scheme int) int {
	if scheme == 0 {
		return getDHOffset0(handshakeBytes)
	} else if scheme == 1 {
		return getDHOffset1(handshakeBytes)
	}
	return -1
}

/**
 * Returns the DH byte offset.
 *
 * @return dh offset
 */
func getDHOffset0(handshakeBytes []byte) int {
	offset := int(handshakeBytes[1532]) + int(handshakeBytes[1533]) + int(handshakeBytes[1534]) + int(handshakeBytes[1535])
	offset = (offset % 632) + 772
	if offset+128 >= 1536 {
		Log("Invalid DH offset")
	}
	return offset
}

/**
 * Returns the DH byte offset.
 *
 * @return dh offset
 */
func getDHOffset1(handshakeBytes []byte) int {
	offset := int(handshakeBytes[768]) + int(handshakeBytes[769]) + int(handshakeBytes[770]) + int(handshakeBytes[771])
	offset = (offset % 632) + 8
	if offset+128 >= 1536 {
		Log("Invalid DH offset")
	}
	return offset
}
func create_s1() []byte {
	s1 := []byte{0, 0, 0, 0, 1, 2, 3, 4}
	rndBytes := make([]byte, HANDSHAKE_SIZE-8)
	for i, _ := range rndBytes {
		rndBytes[i] = byte(rand.Int() % 256)
	}
	s1 = append(s1, rndBytes...)
	return s1
}
func create_s2() []byte {
	rndBytes := make([]byte, HANDSHAKE_SIZE-32)
	for i, _ := range rndBytes {
		rndBytes[i] = byte(rand.Int() % 256)
	}
	return rndBytes
}
