package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Message represents a native messaging request from the browser extension.
type Message struct {
	Action string `json:"action"`
	Domain string `json:"domain,omitempty"`
}

// Response represents a native messaging response to the browser extension.
type Response struct {
	Status  string `json:"status,omitempty"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

func main() {
	// Log to stderr so stdout is reserved for native messaging protocol
	log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

	for {
		msg, err := readMessage(os.Stdin)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Error().Err(err).Msg("failed to read message")
			break
		}

		resp := handleMessage(msg)

		if err := writeMessage(os.Stdout, resp); err != nil {
			log.Error().Err(err).Msg("failed to write response")
			break
		}
	}
}

func readMessage(r io.Reader) (*Message, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	// Sanity check: reject messages larger than 1MB
	if length > 1<<20 {
		return nil, io.ErrUnexpectedEOF
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(buf, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

func writeMessage(w io.Writer, resp *Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, uint32(len(data))); err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

func handleMessage(msg *Message) *Response {
	switch msg.Action {
	case "ping":
		return &Response{Status: "ok", Version: "1.0.0"}
	default:
		return &Response{Error: "unknown action"}
	}
}
