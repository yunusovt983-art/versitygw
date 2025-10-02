// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package ipfs

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

// EncryptedStream represents an encrypted data stream
type EncryptedStream struct {
	Algorithm   string            `json:"algorithm"`
	KeyVersion  int               `json:"key_version"`
	ChunkSize   int               `json:"chunk_size"`
	Metadata    map[string]string `json:"metadata"`
	Chunks      []*EncryptedChunk `json:"chunks"`
	TotalSize   int64             `json:"total_size"`
	mu          sync.RWMutex
}

// EncryptedChunk represents a single encrypted chunk
type EncryptedChunk struct {
	Index      int    `json:"index"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	Size       int    `json:"size"`
}

// NewEncryptedStream creates a new encrypted stream
func NewEncryptedStream(reader io.Reader, cipherSuite CipherSuite, key *DerivedKey, chunkSize int, metadata map[string]string) (*EncryptedStream, error) {
	stream := &EncryptedStream{
		Algorithm:  cipherSuite.Name(),
		KeyVersion: key.Version,
		ChunkSize:  chunkSize,
		Metadata:   metadata,
		Chunks:     make([]*EncryptedChunk, 0),
		TotalSize:  0,
	}

	// Read and encrypt data in chunks
	buffer := make([]byte, chunkSize)
	chunkIndex := 0

	for {
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to read data: %w", err)
		}

		if n == 0 {
			break
		}

		// Encrypt chunk
		chunkData := buffer[:n]
		encData, err := cipherSuite.Encrypt(chunkData, key.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt chunk %d: %w", chunkIndex, err)
		}

		chunk := &EncryptedChunk{
			Index:      chunkIndex,
			Nonce:      encData.Nonce,
			Ciphertext: encData.Ciphertext,
			Size:       n,
		}

		stream.Chunks = append(stream.Chunks, chunk)
		stream.TotalSize += int64(n)
		chunkIndex++

		if err == io.EOF {
			break
		}
	}

	return stream, nil
}

// NewDecryptedStream creates a reader that decrypts an encrypted stream
func NewDecryptedStream(encStream *EncryptedStream, cipherSuite CipherSuite, key *DerivedKey) (io.Reader, error) {
	return &DecryptedStreamReader{
		encStream:   encStream,
		cipherSuite: cipherSuite,
		key:         key,
		currentChunk: 0,
		buffer:      bytes.NewBuffer(nil),
	}, nil
}

// DecryptedStreamReader implements io.Reader for decrypting encrypted streams
type DecryptedStreamReader struct {
	encStream    *EncryptedStream
	cipherSuite  CipherSuite
	key          *DerivedKey
	currentChunk int
	buffer       *bytes.Buffer
	mu           sync.Mutex
}

// Read implements io.Reader interface
func (dsr *DecryptedStreamReader) Read(p []byte) (int, error) {
	dsr.mu.Lock()
	defer dsr.mu.Unlock()

	// If buffer has data, read from it first
	if dsr.buffer.Len() > 0 {
		return dsr.buffer.Read(p)
	}

	// Check if we've read all chunks
	if dsr.currentChunk >= len(dsr.encStream.Chunks) {
		return 0, io.EOF
	}

	// Decrypt next chunk
	chunk := dsr.encStream.Chunks[dsr.currentChunk]
	encData := &EncryptedData{
		Nonce:      chunk.Nonce,
		Ciphertext: chunk.Ciphertext,
	}

	decryptedData, err := dsr.cipherSuite.Decrypt(encData, dsr.key.Key)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt chunk %d: %w", dsr.currentChunk, err)
	}

	// Write decrypted data to buffer
	dsr.buffer.Write(decryptedData)
	dsr.currentChunk++

	// Read from buffer
	return dsr.buffer.Read(p)
}

// StreamEncryptor provides streaming encryption capabilities
type StreamEncryptor struct {
	cipherSuite CipherSuite
	key         *DerivedKey
	chunkSize   int
	buffer      []byte
	chunkIndex  int
	output      chan *EncryptedChunk
	errors      chan error
	done        chan bool
	mu          sync.Mutex
}

// NewStreamEncryptor creates a new stream encryptor
func NewStreamEncryptor(cipherSuite CipherSuite, key *DerivedKey, chunkSize int) *StreamEncryptor {
	return &StreamEncryptor{
		cipherSuite: cipherSuite,
		key:         key,
		chunkSize:   chunkSize,
		buffer:      make([]byte, 0, chunkSize),
		chunkIndex:  0,
		output:      make(chan *EncryptedChunk, 10),
		errors:      make(chan error, 1),
		done:        make(chan bool, 1),
	}
}

// Write implements io.Writer interface
func (se *StreamEncryptor) Write(data []byte) (int, error) {
	se.mu.Lock()
	defer se.mu.Unlock()

	written := 0
	for len(data) > 0 {
		// Calculate how much we can add to current buffer
		available := se.chunkSize - len(se.buffer)
		toWrite := len(data)
		if toWrite > available {
			toWrite = available
		}

		// Add data to buffer
		se.buffer = append(se.buffer, data[:toWrite]...)
		data = data[toWrite:]
		written += toWrite

		// If buffer is full, encrypt and send chunk
		if len(se.buffer) == se.chunkSize {
			if err := se.encryptAndSendChunk(); err != nil {
				return written, err
			}
		}
	}

	return written, nil
}

// Close finalizes the encryption and sends any remaining data
func (se *StreamEncryptor) Close() error {
	se.mu.Lock()
	defer se.mu.Unlock()

	// Encrypt and send any remaining data in buffer
	if len(se.buffer) > 0 {
		if err := se.encryptAndSendChunk(); err != nil {
			return err
		}
	}

	// Signal completion
	close(se.output)
	se.done <- true
	return nil
}

// GetChunks returns a channel of encrypted chunks
func (se *StreamEncryptor) GetChunks() <-chan *EncryptedChunk {
	return se.output
}

// GetErrors returns a channel of errors
func (se *StreamEncryptor) GetErrors() <-chan error {
	return se.errors
}

// encryptAndSendChunk encrypts the current buffer and sends it as a chunk
func (se *StreamEncryptor) encryptAndSendChunk() error {
	if len(se.buffer) == 0 {
		return nil
	}

	// Encrypt buffer
	encData, err := se.cipherSuite.Encrypt(se.buffer, se.key.Key)
	if err != nil {
		se.errors <- fmt.Errorf("failed to encrypt chunk %d: %w", se.chunkIndex, err)
		return err
	}

	// Create chunk
	chunk := &EncryptedChunk{
		Index:      se.chunkIndex,
		Nonce:      encData.Nonce,
		Ciphertext: encData.Ciphertext,
		Size:       len(se.buffer),
	}

	// Send chunk
	select {
	case se.output <- chunk:
		// Chunk sent successfully
	default:
		// Channel is full, this shouldn't happen with proper buffering
		return fmt.Errorf("output channel is full")
	}

	// Reset buffer and increment index
	se.buffer = se.buffer[:0]
	se.chunkIndex++

	return nil
}

// StreamDecryptor provides streaming decryption capabilities
type StreamDecryptor struct {
	cipherSuite CipherSuite
	key         *DerivedKey
	input       chan *EncryptedChunk
	output      chan []byte
	errors      chan error
	done        chan bool
}

// NewStreamDecryptor creates a new stream decryptor
func NewStreamDecryptor(cipherSuite CipherSuite, key *DerivedKey) *StreamDecryptor {
	sd := &StreamDecryptor{
		cipherSuite: cipherSuite,
		key:         key,
		input:       make(chan *EncryptedChunk, 10),
		output:      make(chan []byte, 10),
		errors:      make(chan error, 1),
		done:        make(chan bool, 1),
	}

	// Start decryption goroutine
	go sd.decryptionWorker()

	return sd
}

// AddChunk adds an encrypted chunk for decryption
func (sd *StreamDecryptor) AddChunk(chunk *EncryptedChunk) error {
	select {
	case sd.input <- chunk:
		return nil
	case <-sd.done:
		return fmt.Errorf("decryptor is closed")
	default:
		return fmt.Errorf("input channel is full")
	}
}

// GetDecryptedData returns a channel of decrypted data
func (sd *StreamDecryptor) GetDecryptedData() <-chan []byte {
	return sd.output
}

// GetErrors returns a channel of errors
func (sd *StreamDecryptor) GetErrors() <-chan error {
	return sd.errors
}

// Close closes the decryptor
func (sd *StreamDecryptor) Close() error {
	close(sd.input)
	<-sd.done
	close(sd.output)
	return nil
}

// decryptionWorker processes encrypted chunks
func (sd *StreamDecryptor) decryptionWorker() {
	defer func() {
		sd.done <- true
	}()

	for chunk := range sd.input {
		// Decrypt chunk
		encData := &EncryptedData{
			Nonce:      chunk.Nonce,
			Ciphertext: chunk.Ciphertext,
		}

		decryptedData, err := sd.cipherSuite.Decrypt(encData, sd.key.Key)
		if err != nil {
			sd.errors <- fmt.Errorf("failed to decrypt chunk %d: %w", chunk.Index, err)
			continue
		}

		// Send decrypted data
		select {
		case sd.output <- decryptedData:
			// Data sent successfully
		case <-sd.done:
			// Decryptor is closing
			return
		}
	}
}

// EncryptedStreamWriter implements io.Writer for creating encrypted streams
type EncryptedStreamWriter struct {
	encryptor *StreamEncryptor
	stream    *EncryptedStream
	mu        sync.Mutex
}

// NewEncryptedStreamWriter creates a new encrypted stream writer
func NewEncryptedStreamWriter(cipherSuite CipherSuite, key *DerivedKey, chunkSize int, metadata map[string]string) *EncryptedStreamWriter {
	encryptor := NewStreamEncryptor(cipherSuite, key, chunkSize)
	
	stream := &EncryptedStream{
		Algorithm:  cipherSuite.Name(),
		KeyVersion: key.Version,
		ChunkSize:  chunkSize,
		Metadata:   metadata,
		Chunks:     make([]*EncryptedChunk, 0),
		TotalSize:  0,
	}

	writer := &EncryptedStreamWriter{
		encryptor: encryptor,
		stream:    stream,
	}

	// Start collecting chunks
	go writer.collectChunks()

	return writer
}

// Write implements io.Writer interface
func (esw *EncryptedStreamWriter) Write(data []byte) (int, error) {
	n, err := esw.encryptor.Write(data)
	if err == nil {
		esw.mu.Lock()
		esw.stream.TotalSize += int64(n)
		esw.mu.Unlock()
	}
	return n, err
}

// Close finalizes the encrypted stream
func (esw *EncryptedStreamWriter) Close() error {
	return esw.encryptor.Close()
}

// GetStream returns the completed encrypted stream
func (esw *EncryptedStreamWriter) GetStream() *EncryptedStream {
	esw.mu.Lock()
	defer esw.mu.Unlock()
	return esw.stream
}

// collectChunks collects encrypted chunks from the encryptor
func (esw *EncryptedStreamWriter) collectChunks() {
	for chunk := range esw.encryptor.GetChunks() {
		esw.mu.Lock()
		esw.stream.Chunks = append(esw.stream.Chunks, chunk)
		esw.mu.Unlock()
	}
}

// EncryptedStreamReader implements io.Reader for reading encrypted streams
type EncryptedStreamReader struct {
	stream       *EncryptedStream
	cipherSuite  CipherSuite
	key          *DerivedKey
	currentChunk int
	chunkBuffer  *bytes.Buffer
	mu           sync.Mutex
}

// NewEncryptedStreamReader creates a new encrypted stream reader
func NewEncryptedStreamReader(stream *EncryptedStream, cipherSuite CipherSuite, key *DerivedKey) *EncryptedStreamReader {
	return &EncryptedStreamReader{
		stream:       stream,
		cipherSuite:  cipherSuite,
		key:          key,
		currentChunk: 0,
		chunkBuffer:  bytes.NewBuffer(nil),
	}
}

// Read implements io.Reader interface
func (esr *EncryptedStreamReader) Read(p []byte) (int, error) {
	esr.mu.Lock()
	defer esr.mu.Unlock()

	// If we have data in the buffer, read from it
	if esr.chunkBuffer.Len() > 0 {
		return esr.chunkBuffer.Read(p)
	}

	// Check if we've read all chunks
	if esr.currentChunk >= len(esr.stream.Chunks) {
		return 0, io.EOF
	}

	// Decrypt the next chunk
	chunk := esr.stream.Chunks[esr.currentChunk]
	encData := &EncryptedData{
		Nonce:      chunk.Nonce,
		Ciphertext: chunk.Ciphertext,
	}

	decryptedData, err := esr.cipherSuite.Decrypt(encData, esr.key.Key)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt chunk %d: %w", esr.currentChunk, err)
	}

	// Write decrypted data to buffer
	esr.chunkBuffer.Write(decryptedData)
	esr.currentChunk++

	// Read from buffer
	return esr.chunkBuffer.Read(p)
}

// Seek implements io.Seeker interface (limited support)
func (esr *EncryptedStreamReader) Seek(offset int64, whence int) (int64, error) {
	// For simplicity, only support seeking to the beginning
	if offset == 0 && whence == io.SeekStart {
		esr.mu.Lock()
		defer esr.mu.Unlock()
		
		esr.currentChunk = 0
		esr.chunkBuffer.Reset()
		return 0, nil
	}
	
	return 0, fmt.Errorf("seek operation not supported")
}

// Size returns the total size of the decrypted stream
func (esr *EncryptedStreamReader) Size() int64 {
	return esr.stream.TotalSize
}