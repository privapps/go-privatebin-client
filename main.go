package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/pbkdf2"

	"github.com/matthewpi/privatebin/utils"
)

const (
	specIterations  = 100000
	specKeySize     = 256
	specTagSize     = 128
	specAlgorithm   = "aes"
	specMode        = "gcm"
	specCompression = "none"
)

// PasteRequest .
type PasteRequest struct {
	V     int              `json:"v"`
	AData []interface{}    `json:"adata"`
	Meta  PasteRequestMeta `json:"meta"`
	CT    string           `json:"ct"`
}

// PasteRequestMeta .
type PasteRequestMeta struct {
	Expire string `json:"expire"`
}

// PasteResponse .
type PasteResponse struct {
	Status      int    `json:"status"`
	ID          string `json:"id"`
	URL         string `json:"url"`
	DeleteToken string `json:"deletetoken"`
}

// PasteContent .
type PasteContent struct {
	Paste string `json:"paste"`
}

// PasteSpec .
type PasteSpec struct {
	IV          string
	Salt        string
	Iterations  int
	KeySize     int
	TagSize     int
	Algorithm   string
	Mode        string
	Compression string
}

// SpecArray .
func (spec *PasteSpec) SpecArray() []interface{} {
	return []interface{}{
		spec.IV,
		spec.Salt,
		spec.Iterations,
		spec.KeySize,
		spec.TagSize,
		spec.Algorithm,
		spec.Mode,
		spec.Compression,
	}
}

// PasteData .
type PasteData struct {
	*PasteSpec
	Data []byte
}

// adata .
func (paste *PasteData) adata() []interface{} {
	return []interface{}{
		paste.SpecArray(),
		"plaintext",
		0,
		0,
	}
}

func main() {
	// Read from STDIN (Piped input)
	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	// Remove extra line breaks to prevent PrivateBin from breaking.
	if bytes.HasSuffix(input, []byte("\n")) {
		input = input[:len(input)-1]
	}

	// Marshal the paste content to escape JSON characters.
	pasteContent, err := json.Marshal(&PasteContent{Paste: utils.StripANSI(string(input))})
	if err != nil {
		panic(err)
	}

	var host string
	var dry bool
	var expire string
	var key string

	flag.StringVar(&host, "host", "https://privatebin.net", "private bin host url")
	flag.BoolVar(&dry, "dry", false, "dry run. not send to the host, output json and hash")
	flag.StringVar(&expire, "expire", "1day", "expire time, values[ 1day, 1week, 1month, never ]")
	flag.StringVar(&key, "key", "", "hash key to encrypt")
	flag.Parse()

	var masterKey []byte
	if key != "" {
		masterKey = base58.Decode(key)
	} else {
		// Generate a master key for the paste.
		master, err := utils.GenRandomBytes(32)
		if err != nil {
			panic(err)
		}
		masterKey = master
	}

	// Encrypt the paste data
	pasteData, err := encrypt(masterKey, pasteContent)
	if err != nil {
		panic(err)
	}

	// Create a new Paste Request.
	pasteRequest := &PasteRequest{
		V:     2,
		AData: pasteData.adata(),
		Meta: PasteRequestMeta{
			Expire: expire,
		},
		CT: utils.Base64(pasteData.Data),
	}

	// Get the Request Body.
	body, err := json.Marshal(pasteRequest)
	if err != nil {
		panic(err)
	}

	if dry {
		fmt.Printf("%v\n%v\n", base58.Encode(masterKey), bytes.NewBuffer(body))
		return
	}

	// Create a new HTTP Client and HTTP Request.
	client := &http.Client{}
	req, err := http.NewRequest("POST", host, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}

	// Set the request headers.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("X-Requested-With", "JSONHttpRequest")

	// Run the http request.
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	// Close the request body once we are done.
	defer func() {
		if err := res.Body.Close(); err != nil {
			panic(err)
		}
	}()

	// Read the response body.
	response, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	// Decode the response.
	pasteResponse := &PasteResponse{}
	if err := json.Unmarshal(response, &pasteResponse); err != nil {
		panic(err)
	}

	fmt.Printf("%s%s#%s\n", host, pasteResponse.URL, base58.Encode(masterKey))
}

func encrypt(master []byte, message []byte) (*PasteData, error) {
	// Generate a initialization vector.
	iv, err := utils.GenRandomBytes(12)
	if err != nil {
		return nil, err
	}

	// Generate salt.
	salt, err := utils.GenRandomBytes(8)
	if err != nil {
		return nil, err
	}

	// Create the Paste Data and generate a key.
	paste := &PasteData{
		PasteSpec: &PasteSpec{
			IV:          utils.Base64(iv),
			Salt:        utils.Base64(salt),
			Iterations:  specIterations,
			KeySize:     specKeySize,
			TagSize:     specTagSize,
			Algorithm:   specAlgorithm,
			Mode:        specMode,
			Compression: specCompression,
		},
	}
	key := pbkdf2.Key(master, salt, paste.Iterations, 32, sha256.New)

	// Get the "adata" for the paste.
	adata, err := json.Marshal(paste.adata())
	if err != nil {
		return nil, err
	}

	// Create a new Cipher
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM.
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Sign the message.
	data := gcm.Seal(nil, iv, message, adata)

	// Update and return the paste data.
	paste.Data = data

	return paste, nil
}
