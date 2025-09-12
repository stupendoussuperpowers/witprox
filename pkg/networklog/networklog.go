package networklog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type NetworkRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	DurationMs int64     `json:"duration_ms"`
	Method     string    `json:"method"`
	URL        string    `json:"url"`
	StatusCode int       `json:"status_code"`
	ClientAddr string    `json:"client_addr"`
	BytesSent  int64     `json:"bytes_sent"`
	BytesRecv  int64     `json:"bytes_recv"`
	ReqHash    string    `json:"req_hash"`
	ResHash    string    `json:"res_hash"`
}

func AppendRecord(path string, rec *NetworkRecord) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer f.Close()

	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("write record: %w", err)
	}

	return nil
}

func HashAndReplaceBody(body io.ReadCloser) (string, int64, io.ReadCloser, error) {
	if body == nil {
		return "", 0, nil, nil
	}

	b, err := io.ReadAll(body)

	if err != nil {
		return "", 0, body, err
	}

	body.Close()

	h := sha256.Sum256(b)
	hexh := hex.EncodeToString(h[:])

	return hexh, int64(len(b)), io.NopCloser(bytes.NewReader(b)), nil
}

func BuildNetworkRecord(req *http.Request, resp *http.Response, start, end time.Time, clientAddr string, destAddr string) (*NetworkRecord, error) {
	rec := &NetworkRecord{
		Timestamp:  end.UTC(),
		DurationMs: end.Sub(start).Milliseconds(),
		Method:     req.Method,
		URL:        fmt.Sprintf("%s%s", destAddr, req.URL.String()),
		ClientAddr: clientAddr,
	}

	if req.Body != nil {
		hexh, size, rc, err := HashAndReplaceBody(req.Body)
		if err == nil {
			rec.ReqHash = hexh
			rec.BytesSent = size
			req.Body = rc
		}
	}

	if resp != nil && resp.Body != nil {
		hexh, size, rc, err := HashAndReplaceBody(resp.Body)
		if err == nil {
			rec.ResHash = hexh
			rec.BytesRecv = size
			resp.Body = rc
		}

		rec.StatusCode = resp.StatusCode
	}

	return rec, nil

}
