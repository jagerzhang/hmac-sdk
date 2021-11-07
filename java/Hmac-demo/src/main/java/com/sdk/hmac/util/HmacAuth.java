package com.tencent.netplat.demo.hmac.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author gavin
 * @version 1.0
 * @date 2020/4/5
 **/
public class HmacAuth {
    /**
     * 用户名
     */
    private String userName;

    /**
     * 密钥
     */
    private String secret;

    /**
     * 加密内容
     */
    private String body;

    /**
     * hmac加密算法
     */
    private String hmacAlgo = "HmacSHA256";

    public HmacAuth(String userName, String secret, String body) {
        this.userName = userName;
        this.secret = secret;
        this.body = body;
    }

    public HmacAuth(String userName, String secret, String body, String hmacAlgo){
        this.userName = userName;
        this.secret = secret;
        this.body = body;
        this.hmacAlgo = hmacAlgo;
    }

    /**
     * 生成HmacAuth加密认证header
     * @return 认证的header
     * @throws NoSuchAlgorithmException 加密算法不支持
     * @throws InvalidKeyException 加密密钥异常
     */
    public Map<String, String> genAuthHead() throws NoSuchAlgorithmException, InvalidKeyException {
        // 生成body的sha256加密串
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] digestHash = digest.digest(this.body.getBytes(StandardCharsets.UTF_8));
        String bodyHash = Base64.getEncoder().encodeToString(digestHash);
        String bodyDigest = String.format("SHA-256=%s", bodyHash);

        // 生成当前GMT时间，注意格式不能改变，必须形如：Wed, 14 Aug 2019 09:09:28 GMT
        SimpleDateFormat df = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'");
        df.setTimeZone(TimeZone.getTimeZone("GMT"));
        String timeNow = df.format(new Date());

        // 拼装待签名的数据
        String signData = String.format("date: %s\ndigest: %s", timeNow, bodyDigest);

        // 生成hmac签名
        Mac hmac = Mac.getInstance(this.hmacAlgo);
        hmac.init(new SecretKeySpec(this.secret.getBytes(StandardCharsets.UTF_8), this.hmacAlgo));
        byte[] hmacHash = hmac.doFinal(signData.getBytes(StandardCharsets.UTF_8));
        String hmacSign = Base64.getEncoder().encodeToString(hmacHash);

        // 拼装headers
        Map<String, String> header = new HashMap<>(3);
        String auth = String.format("hmac username=\"%s\", algorithm=\"hmac-sha256\", headers=\"date digest\", signature=\"%s\"", this.userName, hmacSign);
        header.put("Authorization", auth);
        header.put("Digest", bodyDigest);
        header.put("Date", timeNow);
        return header;
    }
}
