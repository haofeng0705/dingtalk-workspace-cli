package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

var (
	sinkMarshal = json.Marshal
	sinkWrite   = func(file *os.File, data []byte) (int, error) { return file.Write(data) }
)

type Sink interface {
	Emit(event *Event) error
	Close() error
}

type NopSink struct{}

func (NopSink) Emit(*Event) error { return nil }
func (NopSink) Close() error      { return nil }

type FileSink struct {
	writer    *DateRotatingWriter
	chain     *Chain
	forwarder *HTTPForwarder
}

func NewFileSink(writer *DateRotatingWriter, chain *Chain, forwarder *HTTPForwarder) *FileSink {
	return &FileSink{
		writer:    writer,
		chain:     chain,
		forwarder: forwarder,
	}
}

func (s *FileSink) Emit(evt *Event) error {
	body, err := marshalWithoutHash(evt)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
	}

	err = appendSealed(s.writer, s.chain, body, func(prevHash, hash string) ([]byte, error) {
		evt.PrevHash, evt.Hash = prevHash, hash
		return sinkMarshal(evt)
	})
	if err == nil && s.forwarder != nil {
		s.forwarder.Forward(*evt)
	}
	return err
}

// appendSealed holds the same lock across reading the tail and appending the
// new record, for both the tool stream and the independent command stream.
func appendSealed(writer *DateRotatingWriter, chain *Chain, body []byte, encode func(prevHash, hash string) ([]byte, error)) error {
	f, release, err := writer.beginAppend()
	if err != nil {
		return fmt.Errorf("audit: acquire writer: %w", err)
	}
	defer release()
	prevHash, hash, err := chain.SealFromFile(f, body)
	if err != nil {
		return fmt.Errorf("audit: seal event: %w", err)
	}
	line, err := encode(prevHash, hash)
	if err != nil {
		return fmt.Errorf("audit: marshal final event: %w", err)
	}
	line = append(line, '\n')
	if _, err := sinkWrite(f, line); err != nil {
		return fmt.Errorf("audit: write event: %w", err)
	}
	return nil
}

// Close flushes in-flight remote forwards (bounded) before closing the writer,
// so events are not silently dropped when the CLI process exits right after
// emitting.
func (s *FileSink) Close() error {
	var forwardErr error
	if s.forwarder != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		forwardErr = s.forwarder.Close(ctx)
		cancel()
	}
	if err := s.writer.Close(); err != nil {
		return err
	}
	return forwardErr
}

func marshalWithoutHash(evt *Event) ([]byte, error) {
	saved := Event{
		Timestamp:     evt.Timestamp,
		ExecutionID:   evt.ExecutionID,
		AgentID:       evt.AgentID,
		Actor:         evt.Actor,
		Product:       evt.Product,
		Command:       evt.Command,
		Endpoint:      evt.Endpoint,
		ParamsSummary: evt.ParamsSummary,
		Result:        evt.Result,
		ErrCategory:   evt.ErrCategory,
		ErrReason:     evt.ErrReason,
		DurationMs:    evt.DurationMs,
		CLIVersion:    evt.CLIVersion,
		OS:            evt.OS,
		Arch:          evt.Arch,
	}
	return sinkMarshal(saved)
}
