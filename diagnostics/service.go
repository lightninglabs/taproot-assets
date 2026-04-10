package diagnostics

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultQueueSize = 64
)

var fileNameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

type storedFailureMetadata struct {
	Timestamp           time.Time `json:"timestamp"`
	Stage               string    `json:"stage"`
	Error               string    `json:"error"`
	AnchorTxID          string    `json:"anchor_txid,omitempty"`
	VPacketIndex        *int      `json:"vpkt_idx,omitempty"`
	VPacketOutputIndex  *int      `json:"vpkt_output_idx,omitempty"`
	TransferOutputIndex *int      `json:"transfer_output_idx,omitempty"`
	OutputProofFiles    []string  `json:"output_proof_files,omitempty"`
	InputProofFiles     []string  `json:"input_proof_files,omitempty"`
}

type queuedFailure struct {
	id      uint64
	failure ProofValidationFailure
}

// Service stores proof-validation diagnostics on disk without blocking the
// caller.
type Service struct {
	rootDir string
	runDir  string

	queue chan queuedFailure

	wg sync.WaitGroup

	started  atomic.Bool
	stopOnce sync.Once

	sequence uint64
	dropped  uint64

	nowFn func() time.Time
}

// NewService creates a diagnostics service rooted at the given directory.
func NewService(rootDir string) (*Service, error) {
	if strings.TrimSpace(rootDir) == "" {
		return nil, fmt.Errorf(
			"diagnostics root directory cannot be empty",
		)
	}

	return newService(rootDir, defaultQueueSize, time.Now), nil
}

func newService(rootDir string, queueSize int,
	nowFn func() time.Time) *Service {

	return &Service{
		rootDir: rootDir,
		queue:   make(chan queuedFailure, queueSize),
		nowFn:   nowFn,
	}
}

// Start initializes the run directory and starts the async writer goroutine.
func (s *Service) Start() error {
	if s.started.Load() {
		return nil
	}

	if err := os.MkdirAll(s.rootDir, 0o700); err != nil {
		return fmt.Errorf("create diagnostics root dir: %w", err)
	}

	runDirName := fmt.Sprintf(
		"ts%d-pid%d", s.nowFn().Unix(), os.Getpid(),
	)
	s.runDir = filepath.Join(s.rootDir, runDirName)

	if err := os.MkdirAll(s.runDir, 0o700); err != nil {
		return fmt.Errorf("create diagnostics run dir: %w", err)
	}

	log.Infof("Diagnostics run directory initialized at %s", s.runDir)

	s.started.Store(true)
	s.wg.Add(1)
	go s.writer()

	return nil
}

// Stop flushes pending writes and stops the diagnostics service.
func (s *Service) Stop() error {
	s.stopOnce.Do(func() {
		close(s.queue)
		s.wg.Wait()
	})

	return nil
}

// RunDir returns the active diagnostics run directory.
func (s *Service) RunDir() string {
	return s.runDir
}

// DroppedReports returns the number of dropped reports due to queue pressure.
func (s *Service) DroppedReports() uint64 {
	return atomic.LoadUint64(&s.dropped)
}

// CaptureProofValidationFailure stores a failure report asynchronously.
//
// The operation is non-blocking. If the queue is full, the report is dropped.
//
//nolint:lll // Signature exceeds 80 chars due exported names.
func (s *Service) CaptureProofValidationFailure(failure ProofValidationFailure) {
	if s == nil || !s.started.Load() {
		return
	}

	queued := queuedFailure{
		id:      atomic.AddUint64(&s.sequence, 1),
		failure: cloneFailure(failure),
	}

	select {
	case s.queue <- queued:
	default:
		atomic.AddUint64(&s.dropped, 1)
		log.Warnf("Diagnostics queue full, dropping proof failure "+
			"report (stage=%s)", failure.Stage)
	}
}

func (s *Service) writer() {
	defer s.wg.Done()

	for report := range s.queue {
		if err := s.writeFailureReport(report); err != nil {
			log.Warnf("Unable to write diagnostics report: %v", err)
		}
	}
}

func (s *Service) writeFailureReport(report queuedFailure) error {
	failure := report.failure
	if failure.Timestamp.IsZero() {
		failure.Timestamp = s.nowFn().UTC()
	}

	stage := sanitizeFileName(failure.Stage)
	if stage == "" {
		stage = "unknown"
	}

	eventDirName := fmt.Sprintf(
		"%d-%s-%06d", failure.Timestamp.Unix(), stage, report.id,
	)
	eventDir := filepath.Join(s.runDir, "proof-failures", eventDirName)
	if err := os.MkdirAll(eventDir, 0o700); err != nil {
		return fmt.Errorf("create diagnostics event dir: %w", err)
	}

	outputNames, err := writeArtifacts(
		eventDir, "output-proof", failure.OutputProofs,
	)
	if err != nil {
		return err
	}

	inputNames, err := writeArtifacts(
		eventDir, "input-proof", failure.InputProofs,
	)
	if err != nil {
		return err
	}

	metadata := storedFailureMetadata{
		Timestamp:           failure.Timestamp.UTC(),
		Stage:               failure.Stage,
		Error:               failure.Error,
		AnchorTxID:          failure.AnchorTxID,
		VPacketIndex:        failure.VPacketIndex,
		VPacketOutputIndex:  failure.VPacketOutputIndex,
		TransferOutputIndex: failure.TransferOutputIndex,
		OutputProofFiles:    outputNames,
		InputProofFiles:     inputNames,
	}

	metaJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal diagnostics metadata: %w", err)
	}

	metaPath := filepath.Join(eventDir, "metadata.json")
	if err := os.WriteFile(metaPath, metaJSON, 0o600); err != nil {
		return fmt.Errorf("write diagnostics metadata: %w", err)
	}

	return nil
}

func writeArtifacts(eventDir, prefix string,
	artifacts []ArtifactFile) ([]string, error) {

	if len(artifacts) == 0 {
		return nil, nil
	}

	writtenNames := make([]string, 0, len(artifacts))
	for idx := range artifacts {
		artifact := artifacts[idx]

		fileName := strings.TrimSpace(artifact.FileName)
		if fileName == "" {
			fileName = fmt.Sprintf("%s-%d.bin", prefix, idx)
		}
		fileName = sanitizeFileName(fileName)
		if fileName == "" {
			fileName = fmt.Sprintf("%s-%d.bin", prefix, idx)
		}

		artifactPath := filepath.Join(eventDir, fileName)
		if err := os.WriteFile(
			artifactPath, artifact.Data, 0o600,
		); err != nil {
			return nil, fmt.Errorf(
				"write artifact %s: %w", fileName, err,
			)
		}

		writtenNames = append(writtenNames, fileName)
	}

	return writtenNames, nil
}

func sanitizeFileName(name string) string {
	sanitized := fileNameSanitizer.ReplaceAllString(name, "-")
	return strings.Trim(sanitized, "-")
}

func cloneFailure(failure ProofValidationFailure) ProofValidationFailure {
	clone := failure
	clone.OutputProofs = cloneArtifacts(failure.OutputProofs)
	clone.InputProofs = cloneArtifacts(failure.InputProofs)
	clone.VPacketIndex = cloneIntPtr(failure.VPacketIndex)
	clone.VPacketOutputIndex = cloneIntPtr(failure.VPacketOutputIndex)
	clone.TransferOutputIndex = cloneIntPtr(failure.TransferOutputIndex)
	return clone
}

func cloneIntPtr(value *int) *int {
	if value == nil {
		return nil
	}

	valueCopy := *value
	return &valueCopy
}

func cloneArtifacts(artifacts []ArtifactFile) []ArtifactFile {
	if len(artifacts) == 0 {
		return nil
	}

	clones := make([]ArtifactFile, 0, len(artifacts))
	for idx := range artifacts {
		artifact := artifacts[idx]
		dataCopy := append([]byte(nil), artifact.Data...)
		clones = append(clones, ArtifactFile{
			FileName: artifact.FileName,
			Data:     dataCopy,
		})
	}

	return clones
}
