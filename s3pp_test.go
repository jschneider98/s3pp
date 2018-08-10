package s3pp

import (
	"testing"
	"time"
	"fmt"
)

var testPolicy *AwsPostPolicy

//
func setTestPolicy() (*AwsPostPolicy) {
	var err error

	if testPolicy != nil {
		return testPolicy
	}

	now := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	later := now.Add(time.Minute)

	testPolicy, err = CreateAwsPostPolicy("aws-id", "aws-secret", "aws-bucket", "aws-region", time.Minute)

	if err != nil {
		panic("Failed to create test policy")
	}

	testPolicy.Expiration = later.Format(time.RFC3339)
	testPolicy.dateStamp = now.Format("20060102")

	return testPolicy
}

//
func TestGetJsonPolicy(t *testing.T) {
	setTestPolicy()

	policy, err := testPolicy.GetJsonPolicy()

	if err != nil {
		t.Error(err)
	}

	fmt.Println(string(policy[:]))
}

//
func TestGetBase64Policy(t *testing.T) {
	setTestPolicy()

	policy, err := testPolicy.GetBase64Policy()

	if err != nil {
		t.Error(err)
	}

	fmt.Println(policy)
}

//
func TestHmacSha256(t *testing.T) {
	setTestPolicy()

	hash := testPolicy.HmacSha256([]byte("key"), []byte("data"))
	match := []byte{80, 49, 254, 61, 152, 156, 109, 21, 55, 160, 19, 250, 110, 115, 157, 162, 52, 99, 253, 174, 195, 183, 1, 55, 216, 40, 227, 106, 206, 34, 27, 208}

	if (string(hash) != string(match)) {
		t.Errorf("Hash mismatch. Expected: '%v' Got: '%v'\n", match, hash)
	}
}

//
func TestGetS3SignatureKey(t *testing.T) {
	setTestPolicy()

	hash := testPolicy.GetS3SignatureKey()
	match := []byte{157, 222, 27, 216, 60, 230, 213, 206, 134, 80, 6, 121, 254, 203, 23, 72, 118, 153, 160, 241, 239, 11, 244, 156, 85, 35, 5, 122, 53, 92, 53, 238}

	if (string(hash) != string(match)) {
		t.Errorf("Hash mismatch. Expected: '%v' Got: '%v'\n", match, hash)
	}
}

//
func TestGetS3Signature(t *testing.T) {
	setTestPolicy()

	hash, err := testPolicy.GetS3Signature()

	if err != nil {
		t.Error(err)
	}

	match := "f7b45fcdf20c933b7a3bc3a0e198b294146a4d339a58dbadb196ae45750ce024"

	if (string(hash) != string(match)) {
		t.Errorf("Hash mismatch. Expected: '%v' Got: '%v'\n", match, hash)
	}
}
