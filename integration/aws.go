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
	IAM IAM
}

// New returns a new AWS integration
func NewAWS() *AWS {
	return &AWS{
		IAM: IAM{},
	}
}

// Check checks that the user's AWS infra is SOC2 compliant
func (a *AWS) Check() (bool, error) {
	return a.IAM.Check()
}

// IAM checks that the user's IAM infra is SOC2 compliant
type IAM struct {
}

func (i *IAM) Check() (bool, error) {
	s, err := session.NewSession()
	if err != nil {
		return false, err
	}

	iamAPI := iam.New(s)

	nonMFAUsers := []string{}

	users, err := iamAPI.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		return false, err
	}
	for _, user := range users.Users {
		mfa, err := iamAPI.ListMFADevices(&iam.ListMFADevicesInput{UserName: user.UserName})
		if err != nil {
			return false, err
		}
		if mfa.MFADevices == nil {
			nonMFAUsers = append(nonMFAUsers, aws.StringValue(user.UserName))
		} else {
			klog.V(4).InfoS("MFA enabled", "user", aws.StringValue(user.UserName))
		}
	}

	if len(nonMFAUsers) > 0 {
		return false, fmt.Errorf("MFA not enabled for users %v", nonMFAUsers)
	}

	return true, nil
}
