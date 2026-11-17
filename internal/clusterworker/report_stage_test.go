package clusterworker

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReportStageLogsOnlyChangedErrors(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	w := &Worker[io.Closer]{}
	mismatch := errors.New("worker security configuration does not match signed policy")
	w.reportStage(mismatch)
	w.reportStage(errors.New(mismatch.Error())) // same message on the next retry: no new log
	w.reportStage(errors.New("other failure"))
	w.reportStage(nil)
	w.reportStage(mismatch) // recurrence after recovery logs again

	require.Equal(t, 3, strings.Count(buf.String(), "Cluster policy staging failed"))
	require.Equal(t, mismatch, w.stageErr)
}
