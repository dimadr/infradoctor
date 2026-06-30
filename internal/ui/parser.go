package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/dimadr/infradoctor/internal/modules"
)

func AskSelection(items []modules.Module) ([]modules.Module, error) {
	ShowMenu(items)

	fmt.Print("Select components (e.g. 1,3,5 or 'all'): ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	input = strings.TrimSpace(input)

	if strings.EqualFold(input, "all") {
		return items, nil
	}

	parsed, err := ParseSelection(input, len(items))
	if err != nil {
		return nil, err
	}

	var selected []modules.Module
	for _, idx := range parsed {
		selected = append(selected, items[idx-1])
	}
	return selected, nil
}

// ParseSelection parses "1,3,5" into valid 1-based indices.
func ParseSelection(input string, max int) ([]int, error) {
	if input == "" {
		return nil, fmt.Errorf("empty selection")
	}

	parts := strings.Split(input, ",")
	var indices []int
	seen := map[int]bool{}

	for _, p := range parts {
		p = strings.TrimSpace(p)
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid number: %q", p)
		}
		if n < 1 || n > max {
			return nil, fmt.Errorf("number %d out of range [1..%d]", n, max)
		}
		if seen[n] {
			return nil, fmt.Errorf("duplicate: %d", n)
		}
		seen[n] = true
		indices = append(indices, n)
	}

	if len(indices) == 0 {
		return nil, fmt.Errorf("no valid selections")
	}

	return indices, nil
}
