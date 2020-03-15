/*
 * Kong HMAC-SHA256签名算法示例
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
 * @author yorkershi
 * @created 2020-3-14
 */

package main

import (
    "konghmac"
    "fmt"
)

func main() {
    username := "<username>"
    secretkey := "<your secret key>"
    body := []byte("request data in body")

    //开始签名, 得到签名字段相关的 HTTP HEADER
    header := konghmac.GetAuthHeader(username, secretkey, body)

    fmt.Println(header)
}
