package com.sdk.hmac;

import com.google.gson.JsonObject;
import com.sdk.hmac.util.HmacAuth;
import okhttp3.*;

import java.util.Map;

/**
 * @author gavin
 * @version 1.0
 * @date 2020/4/5
 **/
public class Sample {
    public static void main(String[] args) throws Exception {
        // 测试样例
        String userName = "<HMAC 账号>";
        String secret = "<HMAC 密钥>";
        JsonObject body = new JsonObject();
        body.addProperty("foo", "oof");
        String param = body.toString();

        // 生成Hmac加密header
        HmacAuth hmac = new HmacAuth(userName, secret, param);
        Map<String, String> authHead = hmac.genAuthHead();
        authHead.put("Content-Type", "application/json");
        System.out.println(authHead);

        // API请求
        String apiUrl = "<带hmac鉴权的接口地址>";
        MediaType JSON = MediaType.parse("application/json; charset=utf-8");
        OkHttpClient client = new OkHttpClient();
        Request.Builder builder = new Request.Builder();
        for(Map.Entry<String, String> entry : authHead.entrySet()){
            String key = entry.getKey();
            String value = entry.getValue();
            builder.addHeader(key, value);
        }

        // POST
        RequestBody requestBody = RequestBody.create(JSON, param);
        Request requestPost = builder
                .url(apiUrl)
                .post(requestBody)
                .build();
        Response resPost = client.newCall(requestPost).execute();
        String retPost = resPost.body().string();
        System.out.println("post res:" + retPost);
    }
}
