package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Manager handles the lifecycle of the Python AI Bridge process.
type Manager struct {
	mu          sync.RWMutex
	client      *Client
	process     *exec.Cmd
	pythonPath  string
	scriptPath  string
	port        int
	running     bool
	available   bool
}

// NewManager creates a bridge manager.
func NewManager(pythonPath, scriptPath string, port int) *Manager {
	if pythonPath == "" {
		pythonPath = "python3"
	}
	if port == 0 {
		port = 9817
	}
	return &Manager{
		pythonPath: pythonPath,
		scriptPath: scriptPath,
		port:       port,
		client:     NewClient(fmt.Sprintf("http://127.0.0.1:%d", port)),
	}
}

// Start launches the Python AI Bridge subprocess.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	// Check if Python and the module are available
	checkCmd := exec.CommandContext(ctx, m.pythonPath, "-c", "import mcp_sct_ai; print('ok')")
	if err := checkCmd.Run(); err != nil {
		log.Printf("Python AI bridge module not found, trying direct script...")

		// Try running the script directly
		if m.scriptPath == "" {
			return fmt.Errorf("AI bridge not available: mcp_sct_ai module not installed and no script path provided")
		}
	}

	// Set up the Python process
	var cmd *exec.Cmd
	if m.scriptPath != "" {
		cmd = exec.CommandContext(ctx, m.pythonPath, m.scriptPath)
	} else {
		cmd = exec.CommandContext(ctx, m.pythonPath, "-m", "mcp_sct_ai.server")
	}

	cmd.Env = append(os.Environ(),
		fmt.Sprintf("MCP_SCT_AI_PORT=%d", m.port),
		"MCP_SCT_AI_HOST=127.0.0.1",
	)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start AI bridge: %w", err)
	}

	m.process = cmd
	m.running = true

	// Wait for the "ready" signal from Python
	readyCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			var status struct {
				Status string `json:"status"`
				Port   int    `json:"port"`
			}
			if err := json.Unmarshal([]byte(line), &status); err == nil && status.Status == "ready" {
				readyCh <- nil
				return
			}
		}
		readyCh <- fmt.Errorf("AI bridge process exited without ready signal")
	}()

	select {
	case err := <-readyCh:
		if err != nil {
			m.Stop()
			return err
		}
	case <-time.After(15 * time.Second):
		m.Stop()
		return fmt.Errorf("AI bridge startup timed out")
	case <-ctx.Done():
		m.Stop()
		return ctx.Err()
	}

	// Verify health
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	health, err := m.client.Health(healthCtx)
	if err != nil {
		log.Printf("AI bridge health check failed: %v", err)
	} else {
		log.Printf("AI bridge started: provider=%s", health.ActiveProvider)
		m.available = true
	}

	// Monitor process
	go m.monitor()

	return nil
}

// Stop gracefully shuts down the Python process.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running || m.process == nil {
		return
	}

	m.running = false
	m.available = false

	// Send SIGTERM
	if m.process.Process != nil {
		_ = m.process.Process.Signal(os.Interrupt)

		// Wait up to 5 seconds
		done := make(chan error, 1)
		go func() { done <- m.process.Wait() }()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = m.process.Process.Kill()
		}
	}

	log.Println("AI bridge stopped")
}

// Client returns the HTTP client for communicating with the AI bridge.
func (m *Manager) Client() *Client {
	return m.client
}

// IsAvailable returns true if the AI bridge is running and healthy.
func (m *Manager) IsAvailable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.available
}

func (m *Manager) monitor() {
	if m.process == nil {
		return
	}
	err := m.process.Wait()
	m.mu.Lock()
	m.running = false
	m.available = false
	m.mu.Unlock()
	if err != nil {
		log.Printf("AI bridge process exited: %v", err)
	} else {
		log.Println("AI bridge process exited normally")
	}
}
