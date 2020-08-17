package com.zhaouri.applelogin.controller;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.zhaouri.applelogin.model.AppleKeys;
import com.zhaouri.applelogin.model.HttpResult;
import com.zhaouri.applelogin.model.Keys;
import com.zhaouri.applelogin.utils.HttpClientUtil;

import org.springframework.web.bind.annotation.*;
import org.apache.commons.codec.binary.Base64;
import com.auth0.jwk.Jwk;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

/**
 * HomeController
 */
@Slf4j
@RestController
@RequestMapping(value = "/")
public class HomeController {

    private Jws<Claims> claims;

    @RequestMapping("/")
    public String index() {

        return "hello";
    }
//    @RequestMapping("/err")
//    public HttpResult err() {
//         HttpResult httpResult = new HttpResult();
//         httpResult.setCode(4);
//         httpResult.setMsg("Error");
//         HashMap map = new HashMap<String,String>();
//         map.put("innnerData",'a');
//        httpResult.setData(map);
//         return httpResult;
//    }

//     @RequestMapping("/error")
//     public Object errors() {
////         HttpResult httpResult = new HttpResult();
//
////         httpResult.setCode(4);
////         httpResult.setMsg("Error");
////         return httpResult;
//         return "error";
//     }

    @RequestMapping(value = "/Decode")
    @ResponseBody
    public HttpResult Decode(@RequestParam("jwt") final String jwt) throws UnsupportedEncodingException{
        final HttpResult httpResult = new HttpResult();
        httpResult.setCode(0);
        httpResult.setMsg("Param Error");
//        final Jws<Claims> claim = jwtParser.parseClaimsJws(jwt);
//        System.out.printf(String.valueOf(claim));


        return httpResult;
    }
    /**
     * 对前端传来的JWT字符串identityToken的第二部分进行解码
     * 主要获取其中的aud和sub，aud大概对应ios前端的包名，sub大概对应当前用户的授权的openID
     * @param identityToken
     * @return  {"aud":"com.xkj.****","sub":"000***.8da764d3f9e34d2183e8da08a1057***.0***","c_hash":"UsKAuEoI-****","email_verified":"true","auth_time":1574673481,"iss":"https://appleid.apple.com","exp":1574674081,"iat":1574673481,"email":"****@qq.com"}
     */
    public static JSONObject parserIdentityToken(String identityToken){
        String[] arr = identityToken.split("\\.");
        Base64 base64 = new Base64();
        String decode = new String (base64.decodeBase64(arr[1]));
        String substring = decode.substring(0, decode.indexOf("}")+1);
        JSONObject jsonObject = JSON.parseObject(substring);
        return  jsonObject;
    }

    /***
     * 苹果登录校验
     *
     * @param jwt 苹果票据 很长很长的一串
     * @param aud iOS包名 eg:com.xxx.xxx
     * @param sub 苹果对应的唯一用户标识
     * @return code 100、success 0、缺少参数 -1 apple identityToken expired -2 apple
     *         identityToken illegal
     */
    @RequestMapping(value = "/appleVerify")
    @ResponseBody
    public HttpResult appleVerify(@RequestParam("jwt") final String jwt, @RequestParam("aud") final String aud,
                                  @RequestParam("sub") final String sub) throws UnsupportedEncodingException {

        final HttpResult httpResult = new HttpResult();
        if (StringUtils.isEmpty(jwt) || StringUtils.isEmpty(aud) || StringUtils.isEmpty(sub)) {
            httpResult.setCode(0);
            httpResult.setMsg("Param Error");
            return httpResult;
        }

        Integer result = -1;

        final String url = "https://appleid.apple.com/auth/keys";
        final String jsonData = HttpClientUtil.httpGetRequest(url);
        final AppleKeys appleKeys = JSONObject.parseObject(jsonData, AppleKeys.class); // 将json字符串转化为JSONObject

        final Base64 base64 = new Base64();
        System.out.println(new String(base64.decode("eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmxpZmV2Yy5pb3NBcHAiLCJleHAiOjE1OTc2MzYwNTQsImlhdCI6MTU5NzYzNTQ1NCwic3ViIjoiMDAwMjc3LjAwOWIxMzM2ZjE4YTQ5MjQ5M2E0MTAxNjZhZmMyODQxLjA0MDQiLCJhdF9oYXNoIjoiN0pqRnROWEdTXzFCVEw1QlU3Zlo0ZyIsImVtYWlsIjoiZG91eGluZG9uZ0BpY2xvdWQuY29tIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIn0"), "UTF-8"));

        String n = "";
        String ee = "";
        List<String> as = Arrays.asList(jwt.split("."));
        System.out.println(as);
        System.out.println(jwt.split("."));

        if (appleKeys.getKeys().size() > 0) {
            // 获得jsonArray的第一个元素
            final Keys keys = appleKeys.getKeys().get(1);

            n = keys.getN();
            ee = keys.getE();

//            log.info("[苹果登录日志]jwt:{},aud:{},sub:{}", jwt, aud, sub);
        }
//        for (keys:appleKeys.getKeys()) {
//            if ()
//        }
//        System.out.printf();
        try {
            final PublicKey kPublicKey = createPublicKey(n, ee);

            result = verify(kPublicKey, jwt, aud, sub);
            if (result == 1) {
                httpResult.setCode(100);
                httpResult.setMsg("success");
                httpResult.setData(claims);
            } else {
                httpResult.setCode(result);
                httpResult.setMsg("fail");
            }

            // log.info("获取公钥结果:" + result + ";" + kPublicKey.toString());
        } catch (final NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (final InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return httpResult;
    }

    public RSAPublicKeySpec build(final String n, final String e) {
        final BigInteger modulus = new BigInteger(1, Base64.decodeBase64(n));
        final BigInteger publicExponent = new BigInteger(1, Base64.decodeBase64(e));
        return new RSAPublicKeySpec(modulus, publicExponent);
    }

    public int verify(final PublicKey key, final String jwt, final String audience, final String subject) {
        final JwtParser jwtParser = Jwts.parser().setSigningKey(key);
        jwtParser.requireIssuer("https://appleid.apple.com");
        jwtParser.requireAudience(audience);
        jwtParser.requireSubject(subject);

        try {
            final Jws<Claims> claim = jwtParser.parseClaimsJws(jwt);
            System.out.printf(String.valueOf(claim));
            if (claim != null && claim.getBody().containsKey("auth_time")) {

                claims = claim;

//                log.info("[Apple登录解密结果]header:{},body:{},signature:{}", claim.getHeader(), claim.getBody(),
//                        claim.getSignature());

                return 1;
            }
            return 0;
        } catch (final ExpiredJwtException e) {
//            log.error("apple identityToken expired");
            e.printStackTrace();
            return -1;
        } catch (final Exception e) {
//            log.error("apple identityToken illegal");
            return -2;
        }
    }

    /**
     * 从hex string生成公钥
     *
     * @param stringN
     * @param stringE
     * @return 构造好的公钥
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey createPublicKey(final String stringN, final String stringE)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            // BigInteger N = new BigInteger(stringN, 16); // hex base
            // BigInteger E = new BigInteger(stringE, 16); // hex base

            final BigInteger modulus = new BigInteger(1, Base64.decodeBase64(stringN));
            final BigInteger publicExponent = new BigInteger(1, Base64.decodeBase64(stringE));

            final RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
            final KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (final Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}