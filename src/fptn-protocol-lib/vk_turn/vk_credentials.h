/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace fptn::protocol::vk_turn {

// Short-lived TURN credentials VK hands out to a participant of a call.
struct TurnCredentials {
  std::string username;
  std::string password;
  std::vector<std::string> servers;  // "host:port", UDP
};

// A text captcha VK may ask to solve before it lets an anonymous user in.
struct CaptchaChallenge {
  std::string sid;
  std::string image_url;
  std::vector<std::uint8_t> image;  // PNG/JPEG bytes, may be empty
};

// Returns the text typed by the user, an empty string cancels.
using CaptchaSolver = std::function<std::string(const CaptchaChallenge&)>;

// "https://vk.com/call/join/<id>", "vk.ru/call/join/<id>?..." or "<id>"
// -> "<id>"; empty when the link is not a VK call link.
std::string ExtractCallId(const std::string& link);

// turn_server object of vchat.joinConversationByLink.
std::optional<TurnCredentials> ParseTurnServer(const nlohmann::json& response);

struct FetchResult {
  std::optional<TurnCredentials> credentials;
  std::string error;
  // Addresses of the VK API servers that were used: they must stay outside
  // the VPN tunnel to fetch new credentials later.
  std::set<std::string> api_addresses;
};

// Joins the call anonymously and returns the TURN credentials. Blocking.
FetchResult FetchTurnCredentials(
    const std::string& call_id, const CaptchaSolver& captcha_solver);

}  // namespace fptn::protocol::vk_turn
