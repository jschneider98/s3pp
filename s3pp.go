package s3pp

import (
	"time"
	"strings"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"crypto/hmac"
	"crypto/sha256"
)

//
type AwsPostPolicy struct {
	elements [17]string
	dateStamp string
	options *AwsPostPolicyOptions
	ConditionMap map[string][3]string `json:"-"`
	Expiration string `json:"expiration"`
	Conditions [][3]string `json:"conditions"`
}

//
func CreateAwsPostPolicy (options *AwsPostPolicyOptions) (*AwsPostPolicy, error) {
	err := options.IsValid()

	if err != nil {
		return nil, err
	}

	policy := &AwsPostPolicy{}
	policy.options = options
	policy.ConditionMap = make(map[string][3]string)
	policy.initElements()

	now := time.Now().UTC()
	later := now.Add(options.Duration)

	policy.Expiration = later.Format(time.RFC3339)
	policy.dateStamp = now.Format("20060102")

	return policy, nil
}

//
func (p *AwsPostPolicy) SetCondition(operator string, element string, value string) [3]string {
	element = strings.ToLower(element)

	condition := [3]string{operator, "$" + element, value}
	p.ConditionMap[element] = condition

	return condition
}

//
func (p * AwsPostPolicy) GetConditions () [][3]string {
	p.Conditions = make([][3]string, 0)
	p.Conditions = append(p.Conditions, [3]string{"eq", "$bucket", p.options.Bucket})

	for _, element := range p.elements {

		if val, ok := p.ConditionMap[element]; ok {
			p.Conditions = append(p.Conditions, val)
		}
	}

	p.Conditions = append(p.Conditions, [3]string{"eq", "$x-amz-meta-uuid", "14365123651274"})
	p.Conditions = append(p.Conditions, [3]string{"eq", "$x-amz-credential", p.options.Id + "/" + p.dateStamp + "/" + p.options.Region + "/s3/aws4_request"})
	p.Conditions = append(p.Conditions, [3]string{"eq", "$x-amz-algorithm", "AWS4-HMAC-SHA256"})
	p.Conditions = append(p.Conditions, [3]string{"eq", "$x-amz-date", p.dateStamp + "T000000Z"})

	return p.Conditions
}

//
func (p *AwsPostPolicy) GetJsonPolicy() ([]byte, error) {
	p.GetConditions()

	return json.Marshal(p)
}

//
func (p *AwsPostPolicy) GetBase64Policy() (string, error) {
	jsonPolicy, err := p.GetJsonPolicy()

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

	secret := "AWS4" + p.options.Secret
	dateKey := p.HmacSha256([]byte(secret), []byte(p.dateStamp))
	dateRegionKey := p.HmacSha256(dateKey, []byte(p.options.Region))
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

//
func (p *AwsPostPolicy) initElements() {
	p.elements[0] = "acl"
	p.elements[1] = "content-length-range"
	p.elements[2] = "cache-control"
	p.elements[3] = "content-type"
	p.elements[4] = "content-disposition"
	p.elements[5] = "content-encoding"
	p.elements[6] = "expires"
	p.elements[7] = "key"
	p.elements[8] = "success_action_redirect"
	p.elements[9] = "redirect"
	p.elements[10] = "success_action_status"
	p.elements[11] = "x-amz-algorithm"
	p.elements[12] = "x-amz-credential"
	p.elements[13] = "x-amz-date"
	p.elements[14] = "x-amz-security-token"
	p.elements[15] = "x-amz-meta-*"
	p.elements[16] = "x-amz-*"
}
