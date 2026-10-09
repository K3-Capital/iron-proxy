// Command workflows converts checked-in workflow YAML to JSON for the
// dependency-free Python policy tests, using the module's existing YAML parser.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	configs := make(map[string]any)
	for _, path := range os.Args[1:] {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var config map[string]any
		if err := yaml.Unmarshal(data, &config); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		configs[path] = config
	}
	if err := json.NewEncoder(os.Stdout).Encode(configs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
