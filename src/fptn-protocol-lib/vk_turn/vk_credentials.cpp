/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/vk_turn/vk_credentials.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <fmt/format.h>     // NOLINT(build/include_order)
#include <openssl/rand.h>   // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/utils/tls/tls.h"

namespace fptn::protocol::vk_turn {

namespace {

namespace http = boost::beast::http;

constexpr int kHttpTimeoutSec = 15;
constexpr int kMaxCaptchaAttempts = 3;
constexpr int kVkCaptchaErrorCode = 14;

constexpr char kUserAgent[] =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "  // NOLINT
    "AppleWebKit/537.36 (KHTML, like Gecko) "     // NOLINT
    "Chrome/146.0.0.0 Safari/537.36";             // NOLINT
// Public application key of the web calls client.
constexpr char kOkApplicationKey[] = "CGMMEJLGDIHBABABA";

// VK Calls web client: anonymous join without the messages API captcha.
constexpr char kCallsClientId[] = "8093730";
constexpr char kCallsApiVersion[] = "5.276";

// Fallback: anonymous token of the VK web application.
constexpr char kWebClientId[] = "6287487";
constexpr char kWebClientSecret[] = "QbYic1K3lEV5kTGiqlq2";
constexpr char kWebApiVersion[] = "5.275";

struct HttpResult {
  int status = 0;
  std::string body;
  std::string error;
};

struct Url {
  std::string host;
  std::string target;
};

std::optional<Url> SplitUrl(const std::string& url) {
  constexpr std::string_view kPrefix = "https://";
  if (!url.starts_with(kPrefix)) {
    return std::nullopt;
  }
  const auto rest = url.substr(kPrefix.size());
  const auto slash = rest.find('/');
  if (slash == std::string::npos) {
    return Url{rest, "/"};
  }
  return Url{rest.substr(0, slash), rest.substr(slash)};
}

std::string UrlEncode(const std::string& value) {
  std::string out;
  for (const unsigned char c : value) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      out += fmt::format("%{:02X}", c);
    }
  }
  return out;
}

std::string RandomUuid() {
  std::array<std::uint8_t, 16> b{};
  RAND_bytes(b.data(), static_cast<int>(b.size()));
  b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x40);
  b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80);
  return fmt::format(
      "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-"
      "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
      b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
      b[12], b[13], b[14], b[15]);
}

std::string RandomName() {
  static const std::array<const char*, 12> kNames = {"Alex", "Ivan", "Maria",
      "Anna", "Dmitry", "Olga", "Sergey", "Elena", "Pavel", "Irina", "Nikita",
      "Daria"};
  std::random_device rd;
  return kNames[rd() % kNames.size()];
}

HttpResult HttpsRequest(http::verb verb,
    const std::string& url,
    const std::string& body,
    std::set<std::string>& used_addresses) {
  HttpResult result;
  const auto parsed = SplitUrl(url);
  if (!parsed) {
    result.error = "bad url";
    return result;
  }
  try {
    boost::asio::io_context ioc;
    boost::asio::ssl::context ctx(https::utils::CreateNewSslCtx());
    // Same as the API client: the credentials are not a secret and the fptn
    // connection inside the relay pins the server certificate on its own.
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream(ioc, ctx);
    https::utils::SetHandshakeSni(stream.native_handle(), parsed->host);

    boost::asio::co_spawn(
        ioc,
        [&]() -> boost::asio::awaitable<void> {
          boost::system::error_code ec;
          auto& tcp = boost::beast::get_lowest_layer(stream);
          tcp.expires_after(std::chrono::seconds(kHttpTimeoutSec));
          boost::asio::ip::tcp::resolver resolver(ioc);
          const auto endpoints = co_await resolver.async_resolve(
              boost::asio::ip::tcp::v4(), parsed->host, "443",
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            result.error = "resolve: " + ec.message();
            co_return;
          }
          const auto endpoint = co_await tcp.async_connect(endpoints,
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            result.error = "connect: " + ec.message();
            co_return;
          }
          used_addresses.insert(endpoint.address().to_string());
          co_await stream.async_handshake(boost::asio::ssl::stream_base::client,
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            result.error = "tls: " + ec.message();
            co_return;
          }
          http::request<http::string_body> req{verb, parsed->target, 11};
          req.set(http::field::host, parsed->host);
          req.set(http::field::user_agent, kUserAgent);
          req.set(http::field::accept, "*/*");
          req.set(http::field::accept_language, "ru-RU,ru;q=0.9,en;q=0.8");
          req.set(http::field::accept_encoding, "identity");
          req.set(http::field::origin, "https://vk.ru");
          req.set(http::field::referer, "https://vk.ru/");
          if (verb == http::verb::post) {
            req.set(
                http::field::content_type, "application/x-www-form-urlencoded");
            req.body() = body;
          }
          req.prepare_payload();
          co_await http::async_write(stream, req,
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            result.error = "write: " + ec.message();
            co_return;
          }
          boost::beast::flat_buffer buffer;
          http::response_parser<http::string_body> parser;
          parser.body_limit(4 * 1024 * 1024);
          co_await http::async_read(stream, buffer, parser,
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            result.error = "read: " + ec.message();
            co_return;
          }
          result.status = static_cast<int>(parser.get().result_int());
          result.body = parser.get().body();
        },
        boost::asio::detached);
    ioc.run();
  } catch (const std::exception& e) {
    result.error = e.what();
  }
  return result;
}

class VkApi final {
 public:
  explicit VkApi(std::set<std::string>& used_addresses)
      : used_addresses_(used_addresses) {}

  // POST and parse the JSON answer, nullopt with `error` set on failure.
  std::optional<nlohmann::json> Call(const std::string& step,
      const std::string& url,
      const std::string& body,
      std::string& error) {
    const auto resp =
        HttpsRequest(http::verb::post, url, body, used_addresses_);
    if (!resp.error.empty()) {
      error = fmt::format("{}: {}", step, resp.error);
      return std::nullopt;
    }
    auto json = nlohmann::json::parse(resp.body, nullptr, false);
    if (json.is_discarded() || !json.is_object()) {
      error = fmt::format("{}: unexpected answer (HTTP {})", step, resp.status);
      return std::nullopt;
    }
    return json;
  }

  std::vector<std::uint8_t> Download(const std::string& url) {
    const auto resp = HttpsRequest(http::verb::get, url, {}, used_addresses_);
    if (!resp.error.empty() || resp.status != 200) {
      return {};
    }
    return {resp.body.begin(), resp.body.end()};
  }

 private:
  std::set<std::string>& used_addresses_;
};

std::string ApiError(const nlohmann::json& json) {
  if (json.contains("error")) {
    const auto& err = json["error"];
    if (err.is_object()) {
      return fmt::format("error {} {}", err.value("error_code", 0),
          err.value("error_msg", err.value("error_description", "")));
    }
    return json.value("error_msg", err.dump());
  }
  if (json.contains("error_code")) {  // OK API style
    return fmt::format(
        "error {} {}", json["error_code"].dump(), json.value("error_msg", ""));
  }
  return {};
}

std::string GetString(
    const nlohmann::json& json, std::initializer_list<const char*> path) {
  const nlohmann::json* node = &json;
  for (const char* key : path) {
    if (!node->is_object() || !node->contains(key)) {
      return {};
    }
    node = &(*node)[key];
  }
  if (node->is_string()) {
    return node->get<std::string>();
  }
  if (node->is_number()) {
    return node->dump();
  }
  return {};
}

// Both flows end the same way: anonymous login to the calls backend and
// joining the call, which returns the TURN server of the conference.
std::optional<TurnCredentials> JoinConversation(VkApi& api,
    const std::string& call_id,
    const std::string& anonym_token,
    const std::string& session_data,
    std::string& error) {
  const auto login =
      api.Call("auth.anonymLogin", "https://calls.okcdn.ru/fb.do",
          fmt::format("session_data={}&method=auth.anonymLogin&format=JSON&"
                      "application_key={}",
              UrlEncode(session_data), kOkApplicationKey),
          error);
  if (!login) {
    return std::nullopt;
  }
  const auto session_key = GetString(*login, {"session_key"});
  if (session_key.empty()) {
    error = "auth.anonymLogin: " + ApiError(*login);
    return std::nullopt;
  }

  const auto join =
      api.Call("vchat.joinConversationByLink", "https://calls.okcdn.ru/fb.do",
          fmt::format("joinLink={}&isVideo=false&protocolVersion=5&"
                      "capabilities=2F7F&anonymToken={}&"
                      "method=vchat.joinConversationByLink&format=JSON&"
                      "application_key={}&session_key={}",
              UrlEncode(call_id), UrlEncode(anonym_token), kOkApplicationKey,
              UrlEncode(session_key)),
          error);
  if (!join) {
    return std::nullopt;
  }
  auto credentials = ParseTurnServer(*join);
  if (!credentials) {
    error = "vchat.joinConversationByLink: " + ApiError(*join);
  }
  return credentials;
}

std::optional<TurnCredentials> FetchViaCallsClient(
    VkApi& api, const std::string& call_id, std::string& error) {
  const std::string device_id = RandomUuid();
  const std::string name = RandomName();
  const std::string link = UrlEncode("https://vk.ru/call/join/" + call_id);
  const std::string api_base = "https://api.vk.ru/method/";

  const auto step1 = api.Call("auth.getAnonymToken",
      api_base + "auth.getAnonymToken",
      fmt::format("v={}&client_id={}&link={}&device_id={}&anonymName={}&"
                  "lang=ru",
          kCallsApiVersion, kCallsClientId, link, device_id, UrlEncode(name)),
      error);
  if (!step1) {
    return std::nullopt;
  }
  const auto token = GetString(*step1, {"response", "token"});
  if (token.empty()) {
    error = "auth.getAnonymToken: " + ApiError(*step1);
    return std::nullopt;
  }

  const auto step2 =
      api.Call("messages.getCallPreview", api_base + "messages.getCallPreview",
          fmt::format("v={}&anonymous_token={}&device_id={}&extended=1&"
                      "fields=first_name,last_name,photo_200&lang=ru&link={}",
              kCallsApiVersion, UrlEncode(token), device_id, link),
          error);
  if (!step2) {
    return std::nullopt;
  }
  const auto user_id = GetString(*step2, {"response", "user_id"});
  const auto secret = GetString(*step2, {"response", "secret"});
  if (user_id.empty() || secret.empty()) {
    error = "messages.getCallPreview: " + ApiError(*step2);
    return std::nullopt;
  }

  const auto step3 = api.Call("messages.getAnonymCallToken",
      api_base + "messages.getAnonymCallToken",
      fmt::format("v={}&anonymous_token={}&device_id={}&link={}&name={}&"
                  "user_id={}&secret={}&lang=ru",
          kCallsApiVersion, UrlEncode(token), device_id, link, UrlEncode(name),
          user_id, UrlEncode(secret)),
      error);
  if (!step3) {
    return std::nullopt;
  }
  const auto call_token = GetString(*step3, {"response", "token"});
  if (call_token.empty()) {
    error = "messages.getAnonymCallToken: " + ApiError(*step3);
    return std::nullopt;
  }

  return JoinConversation(api, call_id, call_token,
      fmt::format(
          R"({{"version":2,"device_id":"{}","client_version":"1.0.1"}})",
          RandomUuid()),
      error);
}

std::optional<TurnCredentials> FetchViaWebClient(VkApi& api,
    const std::string& call_id,
    const CaptchaSolver& captcha_solver,
    std::string& error) {
  const auto step1 = api.Call("get_anonym_token",
      "https://login.vk.ru/?act=get_anonym_token",
      fmt::format("client_id={}&token_type=messages&client_secret={}&version=1&"
                  "app_id={}",
          kWebClientId, kWebClientSecret, kWebClientId),
      error);
  if (!step1) {
    return std::nullopt;
  }
  const auto access_token = GetString(*step1, {"data", "access_token"});
  if (access_token.empty()) {
    error = "get_anonym_token: " + ApiError(*step1);
    return std::nullopt;
  }

  const std::string url = fmt::format(
      "https://api.vk.ru/method/calls.getAnonymousToken?v={}&client_id={}",
      kWebApiVersion, kWebClientId);
  const std::string base_body =
      fmt::format("vk_join_link={}&name={}&access_token={}",
          UrlEncode("https://vk.com/call/join/" + call_id),
          UrlEncode(RandomName()), UrlEncode(access_token));

  std::string body = base_body;
  std::string anonym_token;
  for (int attempt = 0; anonym_token.empty(); ++attempt) {
    const auto step2 = api.Call("calls.getAnonymousToken", url, body, error);
    if (!step2) {
      return std::nullopt;
    }
    anonym_token = GetString(*step2, {"response", "token"});
    if (!anonym_token.empty()) {
      break;
    }
    const bool captcha =
        step2->contains("error") && (*step2)["error"].is_object() &&
        (*step2)["error"].value("error_code", 0) == kVkCaptchaErrorCode;
    if (!captcha) {
      error = "calls.getAnonymousToken: " + ApiError(*step2);
      return std::nullopt;
    }
    if (!captcha_solver) {
      error = "VK asks to solve a captcha";
      return std::nullopt;
    }
    if (attempt >= kMaxCaptchaAttempts) {
      error = "captcha was not accepted";
      return std::nullopt;
    }
    CaptchaChallenge challenge;
    challenge.sid = GetString(*step2, {"error", "captcha_sid"});
    challenge.image_url = GetString(*step2, {"error", "captcha_img"});
    if (challenge.sid.empty() || challenge.image_url.empty()) {
      error = "VK asks for a captcha that can only be solved in a browser";
      return std::nullopt;
    }
    challenge.image = api.Download(challenge.image_url);
    const auto answer = captcha_solver(challenge);
    if (answer.empty()) {
      error = "captcha cancelled";
      return std::nullopt;
    }
    body = fmt::format("{}&captcha_sid={}&captcha_key={}", base_body,
        UrlEncode(challenge.sid), UrlEncode(answer));
  }

  return JoinConversation(api, call_id, anonym_token,
      fmt::format(R"({{"version":2,"device_id":"{}","client_version":1.1,)"
                  R"("client_type":"SDK_JS"}})",
          RandomUuid()),
      error);
}

}  // namespace

std::string ExtractCallId(const std::string& link) {
  std::string id = link;
  // trim spaces
  const auto first = id.find_first_not_of(" \t\r\n");
  const auto last = id.find_last_not_of(" \t\r\n");
  if (first == std::string::npos) {
    return {};
  }
  id = id.substr(first, last - first + 1);

  constexpr std::string_view kMarker = "/call/join/";
  const auto pos = id.find(kMarker);
  if (pos != std::string::npos) {
    id = id.substr(pos + kMarker.size());
  } else if (std::ranges::find(id, '/') != id.end()) {
    return {};
  }
  const auto end = id.find_first_of("?#/");
  if (end != std::string::npos) {
    id = id.substr(0, end);
  }
  for (const unsigned char c : id) {
    if (!std::isalnum(c) && c != '-' && c != '_') {
      return {};
    }
  }
  return id;
}

std::optional<TurnCredentials> ParseTurnServer(const nlohmann::json& response) {
  if (!response.is_object() || !response.contains("turn_server") ||
      !response["turn_server"].is_object()) {
    return std::nullopt;
  }
  const auto& turn = response["turn_server"];
  TurnCredentials credentials;
  credentials.username = turn.value("username", "");
  credentials.password = turn.value("credential", "");
  if (turn.contains("urls") && turn["urls"].is_array()) {
    for (const auto& url : turn["urls"]) {
      if (!url.is_string()) {
        continue;
      }
      // "turn:host:port?transport=udp"; "turns:" needs TLS, skip it
      std::string value = url.get<std::string>();
      constexpr std::string_view kScheme = "turn:";
      if (!value.starts_with(kScheme)) {
        continue;
      }
      const auto query = value.find('?');
      if (query != std::string::npos) {
        if (value.find("transport=tcp", query) != std::string::npos) {
          continue;
        }
        value.resize(query);
      }
      value = value.substr(kScheme.size());
      if (std::ranges::find(value, ':') == value.end()) {
        value += ":3478";
      }
      if (std::find(credentials.servers.begin(), credentials.servers.end(),
              value) == credentials.servers.end()) {
        credentials.servers.push_back(value);
      }
    }
  }
  if (credentials.username.empty() || credentials.password.empty() ||
      credentials.servers.empty()) {
    return std::nullopt;
  }
  return credentials;
}

FetchResult FetchTurnCredentials(
    const std::string& call_id, const CaptchaSolver& captcha_solver) {
  FetchResult result;
  VkApi api(result.api_addresses);

  std::string error;
  result.credentials = FetchViaCallsClient(api, call_id, error);
  if (result.credentials) {
    return result;
  }
  SPDLOG_WARN("VK calls client join failed ({}), trying the web client", error);

  std::string fallback_error;
  result.credentials =
      FetchViaWebClient(api, call_id, captcha_solver, fallback_error);
  if (!result.credentials) {
    result.error = fmt::format("{}; {}", error, fallback_error);
  }
  return result;
}

}  // namespace fptn::protocol::vk_turn
