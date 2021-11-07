/*
 *******************************************************************************
 Copyright 1998 - 2021 Tencent. All Rights Reserved
 file: sample.cpp
 date: 2020-04-02
 author: steven
 desc: http post
 compile: g++ -o sample sample.cpp hmac_auth.cpp -lssl -lpthread -lcurl -lcrypto
 *******************************************************************************
*/
#include <iostream>
#include <sstream>

#include "curl/curl.h"
#include "hmac_auth.h"

static std::string getKeyValue(const std::string &key, const std::string &value) {
  std::ostringstream oss;
  oss << key << ":" << value;
  return oss.str();
}

static size_t writeData(void *ptr, size_t size, size_t nmemb, void *userdata) {
  std::string *ptrStrRes = (std::string *)userdata;
  ulong sizes = size * nmemb;
  if (!ptr) {
    return 0;
  }

  (*ptrStrRes).append(reinterpret_cast<char *> ptr, sizes);

  return sizes;
}

static int postHttpRequest(std::string *ret, const std::string &url, const std::string &params,
                           const AuthInfo &auth_info, int timeout, bool isdebug) {
  ret->clear();

  if (url.empty()) {
    return -1;
  }

  CURL *curl;
  CURLcode res;
  struct curl_slist *slist = NULL;

  curl = curl_easy_init();

  if (!curl) {
    return -1;
  }

  // header
  slist = curl_slist_append(slist, "Connection:close");
  slist = curl_slist_append(slist, "Content-type:application/json");
  slist = curl_slist_append(slist, "Expect:");

  // HMAC
  slist = curl_slist_append(slist, getKeyValue("Date", auth_info.date).c_str());
  slist = curl_slist_append(slist, getKeyValue("Digest", auth_info.digest).c_str());
  slist = curl_slist_append(slist, getKeyValue("Authorization", auth_info.auth).c_str());

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_FILE, ret);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeData);

  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout > 0 ? timeout : 60);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, isdebug ? 2 : 0);

  if (!params.empty()) {
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());
  }

  res = curl_easy_perform(curl);

  // *NOTE* clearup first, then check the ret status
  curl_slist_free_all(slist);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    return -1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  std::string user = "<HMAC 账号>";
  std::string secret = "<HMAC 密钥>";
  std::string params = "{\"params\":{\"author\":\"jagerzhang\"}";

  AuthInfo auth_info;
  HMACAuth hmac_auth(user, secret, "");

  hmac_auth.getAuthInfo(&auth_info);

  std::string ret;
  postHttpRequest(&ret, "<带hmac鉴权的接口地址>", params, auth_info,
                  60, false);

  std::cout << "ret: " << ret << std::endl;

  return 0;
}
