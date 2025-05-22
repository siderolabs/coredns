package dnsserver

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func TestDoQWriterAddPrefix(t *testing.T) {
	byteArray := []byte{0x1, 0x2, 0x3}

	byteArrayWithPrefix := AddPrefix(byteArray)

	if len(byteArrayWithPrefix) != 5 {
		t.Error("Expected byte array with prefix to have length of 5")
	}

	size := int16(byteArrayWithPrefix[0])<<8 | int16(byteArrayWithPrefix[1])
	if size != 3 {
		t.Errorf("Expected prefixed size to be 3, got: %d", size)
	}
}

func TestDoQWriter_ResponseWriterMethods(t *testing.T) {
	localAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}

	writer := &DoQWriter{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}

	if err := writer.TsigStatus(); err != nil {
		t.Errorf("TsigStatus() returned an error: %v", err)
	}

	// this is a no-op, just call it
	writer.TsigTimersOnly(true)
	writer.TsigTimersOnly(false)

	// this is a no-op, just call it
	writer.Hijack()

	if addr := writer.LocalAddr(); addr != localAddr {
		t.Errorf("LocalAddr() = %v, want %v", addr, localAddr)
	}

	if addr := writer.RemoteAddr(); addr != remoteAddr {
		t.Errorf("RemoteAddr() = %v, want %v", addr, remoteAddr)
	}
}

// mockQuicStream is a mock implementation of quic.Stream for testing.
type mockQuicStream struct {
	writer func(p []byte) (n int, err error)
	closer func() error
	closed bool
	data   []byte
}

func (m *mockQuicStream) Write(p []byte) (n int, err error) {
	m.data = append(m.data, p...)
	if m.writer != nil {
		return m.writer(p)
	}
	return len(p), nil
}

func (m *mockQuicStream) Close() error {
	m.closed = true
	if m.closer != nil {
		return m.closer()
	}
	return nil
}

// Required by quic.Stream interface, but not used in these tests
func (m *mockQuicStream) Read(p []byte) (n int, err error)      { return 0, nil }
func (m *mockQuicStream) CancelRead(code quic.StreamErrorCode)  {}
func (m *mockQuicStream) CancelWrite(code quic.StreamErrorCode) {}
func (m *mockQuicStream) SetReadDeadline(t time.Time) error     { return nil }
func (m *mockQuicStream) SetWriteDeadline(t time.Time) error    { return nil }
func (m *mockQuicStream) SetDeadline(t time.Time) error         { return nil }
func (m *mockQuicStream) StreamID() quic.StreamID               { return 0 }
func (m *mockQuicStream) Context() context.Context              { return nil }

func TestDoQWriter_Write(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		streamWriter func(p []byte) (n int, err error)
		expectErr    bool
		expectedData []byte
		expectedN    int
	}{
		{
			name:  "successful write",
			input: []byte{0x1, 0x2, 0x3},
			streamWriter: func(p []byte) (n int, err error) {
				return len(p), nil
			},
			expectErr:    false,
			expectedData: []byte{0x0, 0x3, 0x1, 0x2, 0x3}, // 3-byte length prefix
			expectedN:    5,
		},
		{
			name:  "stream write error",
			input: []byte{0x4, 0x5},
			streamWriter: func(p []byte) (n int, err error) {
				return 0, errors.New("stream error")
			},
			expectErr:    true,
			expectedData: []byte{0x0, 0x2, 0x4, 0x5}, // 2-byte length prefix
			expectedN:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStream := &mockQuicStream{writer: tt.streamWriter}
			writer := &DoQWriter{stream: mockStream}

			n, err := writer.Write(tt.input)

			if (err != nil) != tt.expectErr {
				t.Errorf("Write() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			if n != tt.expectedN {
				t.Errorf("Write() n = %v, want %v", n, tt.expectedN)
			}

			if !bytes.Equal(mockStream.data, tt.expectedData) {
				t.Errorf("Write() data written to stream = %X, want %X", mockStream.data, tt.expectedData)
			}
		})
	}
}

func TestDoQWriter_WriteMsg(t *testing.T) {
	newMsg := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}

	tests := []struct {
		name         string
		msg          *dns.Msg
		mockStream   *mockQuicStream
		expectErr    bool
		expectClosed bool
		expectedData []byte // Expected data written to stream (packed msg with prefix)
		packErr      bool   // Simulate error during msg.Pack()
	}{
		{
			name:         "successful write and close",
			msg:          newMsg(),
			mockStream:   &mockQuicStream{},
			expectErr:    false,
			expectClosed: true,
		},
		{
			name:         "msg.Pack() error",
			msg:          new(dns.Msg),
			mockStream:   &mockQuicStream{},
			expectErr:    true,
			packErr:      true,  // We'll make msg.Pack() fail by corrupting the msg or using a mock
			expectClosed: false, // Close should not be called if Pack fails
		},
		{
			name: "stream write error",
			msg:  newMsg(),
			mockStream: &mockQuicStream{
				writer: func(p []byte) (n int, err error) {
					return 0, errors.New("stream write failed")
				},
			},
			expectErr:    true,
			expectClosed: false, // Close should not be called if Write fails
		},
		{
			name: "stream close error",
			msg:  newMsg(),
			mockStream: &mockQuicStream{
				closer: func() error {
					return errors.New("stream close failed")
				},
			},
			expectErr:    true,
			expectClosed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.packErr {
				// Intentionally make the message invalid to cause a pack error.
				// Invalid Rcode to ensure Pack fails.
				tt.msg.Rcode = 1337
			}

			writer := &DoQWriter{stream: tt.mockStream, Msg: tt.msg}
			err := writer.WriteMsg(tt.msg)

			if (err != nil) != tt.expectErr {
				t.Errorf("WriteMsg() error = %v, expectErr %v", err, tt.expectErr)
			}

			if tt.mockStream.closed != tt.expectClosed {
				t.Errorf("WriteMsg() stream closed = %v, want %v", tt.mockStream.closed, tt.expectClosed)
			}

			if tt.packErr {
				if len(tt.mockStream.data) != 0 {
					t.Errorf("WriteMsg() data written to stream on pack error = %X, want empty", tt.mockStream.data)
				}
			}
		})
	}
}

func TestDoQWriter_Close(t *testing.T) {
	tests := []struct {
		name       string
		mockStream *mockQuicStream
		expectErr  bool
	}{
		{
			name:       "successful close",
			mockStream: &mockQuicStream{},
			expectErr:  false,
		},
		{
			name: "stream close error",
			mockStream: &mockQuicStream{
				closer: func() error {
					return errors.New("stream close error")
				},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := &DoQWriter{stream: tt.mockStream}
			err := writer.Close()

			if (err != nil) != tt.expectErr {
				t.Errorf("Close() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !tt.mockStream.closed {
				t.Errorf("Close() stream not marked as closed")
			}
		})
	}
}
