// Copyright 1998 - 2020 Tencent. All Rights Reserved

#ifndef _DATA_LANDUN_WORKSPACE_CPP_SRC_HMAC_AUTH_H_
#define _DATA_LANDUN_WORKSPACE_CPP_SRC_HMAC_AUTH_H_

#include <string>

struct AuthInfo {
  std::string date;  // GMT
  std::string digest;
  std::string auth;
};

class HMACAuth {
 public:
  HMACAuth(const std::string &user, const std::string &secret, const std::string &body);

  int getAuthInfo(AuthInfo *auth_info);

 private:
  std::string base64Encode(const std::string &text);
  std::string sha256Encrypt(const std::string &text);
  std::string getDigest(const std::string &body);
  std::string hmacEncrypt(const std::string &secret, const std::string &text);
  std::string getGMTTime();

 private:
  std::string user_;
  std::string secret_;
  std::string body_;
};

#endif  //  _DATA_LANDUN_WORKSPACE_CPP_SRC_HMAC_AUTH_H_