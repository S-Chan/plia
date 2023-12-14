package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	klog "k8s.io/klog/v2"

	"github.com/S-Chan/plio/integration"
)

// Integration represents the schema for an Integration
type Integration struct {
	Name string `json:"name"`
}

// AWSIntegrationResponse represents the response schema for AWS integration
type AWSIntegrationResponse struct {
	Info   string `json:"info"`
	Status string `json:"status"`
}

// getIntegrations handles the /integrations endpoint
func getIntegrations(w http.ResponseWriter, _ *http.Request) {
	response := []Integration{
		{Name: "AWS"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// runAWSIntegration handles the /integrations/aws endpoint
func runAWSIntegration(w http.ResponseWriter, _ *http.Request) {
	awsResp := func(info, status string) {
		response := AWSIntegrationResponse{
			Info:   info,
			Status: status,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}

	aws, err := integration.NewAWS()
	if err != nil {
		klog.ErrorS(err, "Failed to create AWS integration")
		awsResp("Failed to create AWS integration", "error")
		return
	}

	if err = aws.Check(); err != nil {
		klog.ErrorS(err, "AWS check failed")
		awsResp(fmt.Sprintf("%v", err), "noncompliant")
		return
	}

	awsResp("IAM check completed successfully", "ok")
}

func main() {
	http.HandleFunc("/integrations", getIntegrations)
	http.HandleFunc("/integrations/aws", runAWSIntegration)

	if err := http.ListenAndServe(":8000", nil); err != nil {
		klog.Fatalf("Failed to start server: %v", err)
	}
}
