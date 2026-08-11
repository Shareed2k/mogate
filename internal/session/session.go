package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

type Task struct {
	Name string
	Run  func(context.Context) error
}

type result struct {
	name string
	err  error
}

// Run owns cancellation, draining, and error selection for an Injection
// Session. Completion of any task ends the session and all tasks are drained.
func Run(ctx context.Context, tasks ...Task) error {
	if len(tasks) == 0 {
		return errors.New("Injection Session requires at least one task")
	}
	for _, task := range tasks {
		if task.Name == "" || task.Run == nil {
			return errors.New("Injection Session task requires a name and runner")
		}
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(tasks))
	for _, task := range tasks {
		task := task
		go func() { results <- result{name: task.Name, err: task.Run(sessionCtx)} }()
	}
	completed := make([]result, 0, len(tasks))
	completed = append(completed, <-results)
	cancel()
	for len(completed) < len(tasks) {
		completed = append(completed, <-results)
	}
	for _, item := range completed {
		if item.err != nil && !errors.Is(item.err, context.Canceled) {
			return fmt.Errorf("%s: %w", item.name, item.err)
		}
	}
	return nil
}

func WaitForSocket(ctx context.Context, path string, taskResult <-chan error) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		select {
		case err := <-taskResult:
			if err == nil {
				return errors.New("task stopped before socket became ready")
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
