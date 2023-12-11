package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "plio",
		Short: "plio checks if your infra is SOC2 compliant",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("Hello World")
		},
	}

	rootCmd.Execute()
}
