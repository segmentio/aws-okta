package okta

import (
	"os"
	"testing"
)

func TestAwsConfig(t *testing.T) {
	pwd, _ := os.Getwd()
	awsConfig := &AwsConfig{
		File: pwd + "/testdata/config.ini",
	}
	err := awsConfig.Load()
	if err != nil {
		t.Error(err)
	}

	profile := "stage"
	arn := awsConfig.GetProfileArn(profile)
	if arn == "" {
		t.Errorf("role_arn not found in profile %s", profile)
	}
}
