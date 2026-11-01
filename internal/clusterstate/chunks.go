package clusterstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jackc/pgx/v5"
	"hash"
	"io"
	"rauth/internal/clusterpolicy"
)

type chunkWriter struct {
	ctx     context.Context
	tx      pgx.Tx
	cluster string
	blob    clusterpolicy.Blob
	part    int
	total   int64
	buffer  []byte
}

func (w *chunkWriter) flush() error {
	if len(w.buffer) == 0 {
		return nil
	}
	_, err := w.tx.Exec(w.ctx, `INSERT INTO cluster_policy_chunks(cluster_id,sha256,part,payload) VALUES($1,$2,$3,$4)`, w.cluster, w.blob.SHA256, w.part, w.buffer)
	if err != nil {
		return err
	}
	w.part++
	w.buffer = w.buffer[:0]
	return nil
}
func (w *chunkWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.blob.Bytes-w.total {
		return 0, clusterpolicy.ErrInvalid
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), chunkBytes-len(w.buffer))
		w.buffer = append(w.buffer, p[:n]...)
		w.total += int64(n)
		written += n
		p = p[n:]
		if len(w.buffer) == chunkBytes {
			if err := w.flush(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

type stagingReader struct {
	io.Reader
	source io.ReadCloser
	writer *chunkWriter
}

func (r *stagingReader) Close() error {
	err := r.source.Close()
	if err != nil {
		return err
	}
	if r.writer.total != r.writer.blob.Bytes {
		return clusterpolicy.ErrInvalid
	}
	return r.writer.flush()
}

type chunkReader struct {
	rows   pgx.Rows
	blob   clusterpolicy.Blob
	part   int
	total  int64
	digest hash.Hash
	buffer []byte
	err    error
	done   bool
	owner  pgx.Tx
	cancel context.CancelFunc
}

func openChunks(ctx context.Context, tx pgx.Tx, cluster string, b clusterpolicy.Blob) (*chunkReader, error) {
	rows, err := tx.Query(ctx, `SELECT part,payload FROM cluster_policy_chunks WHERE cluster_id=$1 AND sha256=$2 ORDER BY part`, cluster, b.SHA256)
	if err != nil {
		return nil, err
	}
	return &chunkReader{rows: rows, blob: b, digest: sha256.New()}, nil
}
func (r *chunkReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.done {
		return 0, io.EOF
	}
	if len(r.buffer) == 0 {
		if !r.rows.Next() {
			r.err = r.rows.Err()
			r.rows.Close()
			if r.err == nil && (r.total != r.blob.Bytes || hex.EncodeToString(r.digest.Sum(nil)) != r.blob.SHA256) {
				r.err = ErrCorrupt
			}
			if r.err != nil {
				return 0, r.err
			}
			r.done = true
			return 0, io.EOF
		}
		var part int
		var body []byte
		if err := r.rows.Scan(&part, &body); err != nil {
			r.err = err
			r.rows.Close()
			return 0, err
		}
		if part != r.part || len(body) == 0 || len(body) > chunkBytes || int64(len(body)) > r.blob.Bytes-r.total {
			r.err = ErrCorrupt
			r.rows.Close()
			return 0, r.err
		}
		r.part++
		r.total += int64(len(body))
		_, _ = r.digest.Write(body)
		r.buffer = body
	}
	n := copy(p, r.buffer)
	r.buffer = r.buffer[n:]
	return n, nil
}
func (r *chunkReader) Close() error {
	r.rows.Close()
	if r.owner != nil {
		rollback(r.owner)
		r.owner = nil
	}
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	return r.err
}
