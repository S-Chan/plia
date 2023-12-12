package integration

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	klog "k8s.io/klog/v2"
)

// AWS checks that the user's AWS infra is SOC2 compliant
type AWS struct {
	IAM *IAM
}

// New returns a new AWS integration
func NewAWS() (*AWS, error) {
	s, err := session.NewSession()
	if err != nil {
		return nil, err
	}

	return &AWS{IAM: NewIAM(s)}, nil
}

// Check checks that the user's AWS infra is SOC2 compliant
func (a *AWS) Check() error {
	return a.IAM.Check()
}

// IAM checks that the user's IAM infra is SOC2 compliant
type IAM struct {
	iamAPI *iam.IAM
}

// NewIAM returns a new IAM integration
func NewIAM(s *session.Session) *IAM {
	return &IAM{iamAPI: iam.New(s)}
}

// Check checks that the user's IAM infra is SOC2 compliant
func (i *IAM) Check() error {
	return i.checkConsoleMFA()
}

// checkConsoleMFA checks that IAM users with console access have MFA enabled
func (i *IAM) checkConsoleMFA() error {
	nonMFAUsers := []string{}

	users, err := i.iamAPI.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		return err
	}
	for _, user := range users.Users {
		mfa, err := i.iamAPI.ListMFADevices(&iam.ListMFADevicesInput{UserName: user.UserName})
		if err != nil {
			return err
		}
		_, err = i.iamAPI.GetLoginProfile(&iam.GetLoginProfileInput{UserName: user.UserName})
		if err != nil {
			klog.V(4).InfoS("User does not have console access; skipping MFA check", "user", aws.StringValue(user.UserName))
			continue
		}

		if mfa.MFADevices == nil {
			nonMFAUsers = append(nonMFAUsers, aws.StringValue(user.UserName))
		} else {
			klog.V(4).InfoS("MFA enabled", "user", aws.StringValue(user.UserName))
		}
	}

	if len(nonMFAUsers) > 0 {
		return fmt.Errorf("MFA not enabled for users %v", nonMFAUsers)
	}

	return nil
}
