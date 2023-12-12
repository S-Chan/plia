package main

import (
	"flag"

	"github.com/spf13/cobra"
	klog "k8s.io/klog/v2"

	"github.com/S-Chan/plio/integration"
)

func main() {
	var fs flag.FlagSet
	klog.InitFlags(&fs)
	defer klog.Flush()

	rootCmd := &cobra.Command{
		Use:   "plio",
		Short: "plio checks if your infra is SOC2 compliant",
		Run: func(cmd *cobra.Command, _ []string) {
			aws, err := integration.NewAWS()
			if err != nil {
				klog.Exitf("Failed to create AWS integration: %v", err)
			}
			_, err = aws.Check()
			if err != nil {
				klog.Exitf("AWS check failed: %v", err)
			}
		},
	}

	rootCmd.Flags().AddGoFlagSet(&fs)
	rootCmd.Execute()
}
