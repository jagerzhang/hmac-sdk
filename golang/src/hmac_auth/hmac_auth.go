//Package hmac HMAC-SHA256签名
//@author yorker
//@created 2020-3-13
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

//获取Hmac签名头部
//username 用户名
//secretkey 密钥
//body 请求体数据
func GetAuthHeader(username, secretkey string, body []byte) map[string]string {
	//生成body的sha256加密串
	bodyDigest := _sha256DigestBase64(body)

	gmTime := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")

	//拼装待签名的数据
	strToSign := fmt.Sprintf("date: %s\ndigest: %s", gmTime, bodyDigest)

	//生成签名
	signature := _hmacSha256Base64(secretkey, strToSign)

	authStr := fmt.Sprintf(`hmac username="%s", algorithm="hmac-sha256", headers="date digest", signature="%s"`,
		username, signature)
	return map[string]string{
		"Authorization": authStr,
		"Digest":        bodyDigest,
		"Date":          gmTime,
	}
}

func _sha256DigestBase64(body []byte) string {
	sha := sha256.New()
	sha.Write(body)
	return fmt.Sprintf("SHA-256=%s", base64.StdEncoding.EncodeToString(sha.Sum(nil)))
}

func _hmacSha256Base64(secretkey, strToSign string) string {
	h := hmac.New(sha256.New, []byte(secretkey))
	h.Write([]byte(strToSign))
	result := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(result)
}
