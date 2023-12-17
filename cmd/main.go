package main

import (
	"encoding/json"
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
				klog.Exitf("AWS integration creation failed: %v", err)
			}
			res, err := aws.Check()
			if err != nil {
				klog.Exitf("AWS check failed: %v", err)
			}
			// convert res to json and print out using command
			jsonRes, err := json.Marshal(res)
			if err != nil {
				klog.Exitf("result serialization failed: %v", err)
			}
			cmd.Println(string(jsonRes))
		},
	}

	rootCmd.Flags().AddGoFlagSet(&fs)
	rootCmd.Execute()
}
