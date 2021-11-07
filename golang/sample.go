/*
 * HMAC-SHA256签名算法示例
 * 示例运行方式:
 *
 * 将sample.go文件所在的目录路径设置到环境变量GOPATH中，然后执行以下命令
 *
 * windows下:
 * go build sample.go && sample.exe
 *
 * linux下:
 * go build sample.go && ./sample
 *
 * @author yorker
 * @created 2020-3-14
 */

package main

import (
	"bytes"
	"fmt"
	"hmac_auth"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	username := "<HMAC 账号>"
	secretkey := "<HMAC 密钥>"

	//
	//POST请求方式 begin
	//
	fmt.Println("====> Start POST Request")

	//请求体
	body := []byte("request data in body")

	//开始签名, 得到签名字段相关的 HTTP HEADER
	header := hmac_auth.GetAuthHeader(username, secretkey, body)
	//fmt.Println(header)

	url := "<带hmac鉴权的接口地址>"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Println(err.Error())
		return
	}

	//设置头部
	for k, v := range header {
		req.Header.Set(k, v)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err.Error())
		return
	}

	fmt.Println(string(content))
	fmt.Println("<==== POST Request END")

	//
	//GET请求方式 begin
	//
	fmt.Println("\n\n====> Start GET Request")

	//开始签名, 得到签名字段相关的 HTTP HEADER
	header = konghmac.GetAuthHeader(username, secretkey, nil)
	//fmt.Println(header)

	req, err = http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Println(err.Error())
		return
	}

	//设置头部
	for k, v := range header {
		req.Header.Set(k, v)
	}

	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer resp.Body.Close()

	content, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err.Error())
		return
	}

	fmt.Println(string(content))
	fmt.Println("<==== GET Request END")

}
