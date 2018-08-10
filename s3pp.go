package s3pp

import (
	//"fmt"
	//"bytes"
	"time"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"crypto/hmac"
	"crypto/sha256"
)

//
type AwsPostPolicy struct {
	id string
	secret string
	bucket string
	region string
	dateStamp string
	duration time.Duration
	Expiration string `json:"expiration"`
	Conditions [][]string `json:"conditions"`
}

//
func CreateAwsPostPolicy (id string, secret string, bucket string, region string, duration time.Duration) (*AwsPostPolicy, error) {
	policy := &AwsPostPolicy{}
	now := time.Now().UTC()
	later := now.Add(duration)

	policy.Expiration = later.Format(time.RFC3339)
	policy.dateStamp = now.Format("20060102")

	return policy, nil
}

//
func (p *AwsPostPolicy) GetJsonPolicy() ([]byte, error) {
	return json.Marshal(p)
}

//
func (p *AwsPostPolicy) GetBase64Policy() (string, error) {
	jsonPolicy, err := json.Marshal(p)

	if err != nil {
		return "", err
	}

	policy := base64.StdEncoding.EncodeToString(jsonPolicy)

	return policy, nil
}

//
func (p *AwsPostPolicy) GetS3Signature() (string, error) {
	signingKey := p.GetS3SignatureKey()
	base64Policy, err := p.GetBase64Policy()

	if err != nil {
		return "", nil
	}

	s3Signature := p.HmacSha256(signingKey, []byte(base64Policy))
	
	return hex.EncodeToString(s3Signature), nil
}

//
func (p *AwsPostPolicy) GetS3SignatureKey() []byte {

	secret := "AWS4" + p.secret
	dateKey := p.HmacSha256([]byte(secret), []byte(p.dateStamp))
	dateRegionKey := p.HmacSha256(dateKey, []byte(p.region))
	dateRegionServiceKey := p.HmacSha256(dateRegionKey, []byte("s3"))
	signingKey := p.HmacSha256(dateRegionServiceKey, []byte("aws4_request"))

	return signingKey
}

//
func (p *AwsPostPolicy) HmacSha256(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)

	return mac.Sum(nil)
}
