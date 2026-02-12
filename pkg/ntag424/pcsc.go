package ntag424

import (
	"fmt"

	"github.com/ebfe/scard"
)

// Connection wraps a PC/SC card connection.
// From update/internal/pcsc/pcsc.go.
type Connection struct {
	ctx       *scard.Context
	Card      *scard.Card
	Reader    string
	ReaderIdx int
}

// Connect establishes a connection to a card reader.
//
// Parameters:
//   - readerIndex: Index of the reader to use (0-based)
//
// Returns:
//   - Connection struct with context and card
//   - Error if connection fails
func Connect(readerIndex int) (*Connection, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("EstablishContext failed: %w", err)
	}

	readers, err := ctx.ListReaders()
	if err != nil || len(readers) == 0 {
		ctx.Release()
		return nil, fmt.Errorf("no readers found: %v", err)
	}
	if readerIndex < 0 || readerIndex >= len(readers) {
		ctx.Release()
		return nil, fmt.Errorf("reader index out of range (0..%d)", len(readers)-1)
	}

	reader := readers[readerIndex]
	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		ctx.Release()
		return nil, fmt.Errorf("connect failed: %w", err)
	}

	return &Connection{
		ctx:       ctx,
		Card:      card,
		Reader:    reader,
		ReaderIdx: readerIndex,
	}, nil
}

// Close disconnects the card and releases the PC/SC context.
func (c *Connection) Close() {
	if c == nil {
		return
	}
	if c.Card != nil {
		_ = c.Card.Disconnect(scard.LeaveCard)
	}
	if c.ctx != nil {
		_ = c.ctx.Release()
	}
}

// Transmit sends an APDU to the card (implements Card interface).
func (c *Connection) Transmit(apdu []byte) ([]byte, error) {
	if c == nil || c.Card == nil {
		return nil, fmt.Errorf("connection not established")
	}
	return c.Card.Transmit(apdu)
}
