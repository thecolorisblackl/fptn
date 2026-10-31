/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/vk_turn/kcp_pipe.h"
#include "fptn-protocol-lib/vk_turn/stun.h"
#include "fptn-protocol-lib/vk_turn/vk_credentials.h"

using boost::asio::ip::make_address;
using boost::asio::ip::udp;
namespace stun = fptn::protocol::vk_turn::stun;
namespace vk_turn = fptn::protocol::vk_turn;

TEST(VkTurnStun, BuildAndParseRequest) {
  const auto id = stun::NewTransactionId();
  stun::MessageBuilder builder(stun::kChannelBind, stun::kRequest, id);
  builder.AddUint32(stun::kChannelNumber, 0x40000000);
  const udp::endpoint peer4(make_address("203.0.113.7"), 56000);
  const udp::endpoint peer6(make_address("2001:db8::1"), 443);
  builder.AddXorAddress(stun::kXorPeerAddress, peer4);
  builder.AddXorAddress(stun::kXorRelayedAddress, peer6);
  builder.AddString(stun::kUsername, "user");
  const auto bytes = builder.Build(stun::LongTermKey("user", "realm", "pw"));

  ASSERT_EQ(bytes.size() % 4, 0U);
  const auto msg = stun::Parse(bytes.data(), bytes.size());
  ASSERT_TRUE(msg.has_value());
  EXPECT_EQ(msg->method, stun::kChannelBind);
  EXPECT_EQ(msg->message_class, stun::kRequest);
  EXPECT_EQ(msg->transaction_id, id);
  EXPECT_EQ(msg->GetUint32(stun::kChannelNumber), 0x40000000U);
  EXPECT_EQ(msg->GetXorAddress(stun::kXorPeerAddress), peer4);
  EXPECT_EQ(msg->GetXorAddress(stun::kXorRelayedAddress), peer6);
  EXPECT_EQ(msg->GetString(stun::kUsername), "user");
  // MESSAGE-INTEGRITY then FINGERPRINT close the message
  ASSERT_GE(msg->attributes.size(), 2U);
  EXPECT_EQ(msg->attributes[msg->attributes.size() - 2].first,
      stun::kMessageIntegrity);
  EXPECT_EQ(msg->attributes.back().first, stun::kFingerprint);
}

TEST(VkTurnStun, ParseErrorResponse) {
  const auto id = stun::NewTransactionId();
  stun::MessageBuilder builder(stun::kAllocate, stun::kError, id);
  const std::vector<std::uint8_t> error = {0, 0, 4, 1, 'U', 'n', 'a', 'u'};
  builder.AddAttribute(stun::kErrorCode, error.data(), error.size());
  builder.AddString(stun::kNonce, "abc");
  const auto bytes = builder.Build({});
  const auto msg = stun::Parse(bytes.data(), bytes.size());
  ASSERT_TRUE(msg.has_value());
  EXPECT_EQ(msg->method, stun::kAllocate);
  EXPECT_EQ(msg->message_class, stun::kError);
  EXPECT_EQ(msg->ErrorCode(), 401);
  EXPECT_EQ(msg->GetString(stun::kNonce), "abc");
}

TEST(VkTurnStun, RejectsGarbage) {
  const std::vector<std::uint8_t> junk(40, 0x17);
  EXPECT_FALSE(stun::Parse(junk.data(), junk.size()).has_value());
  EXPECT_FALSE(stun::IsChannelData(junk.data(), junk.size()));
}

TEST(VkTurnStun, ChannelData) {
  const std::vector<std::uint8_t> payload = {1, 2, 3, 4, 5};
  const auto bytes =
      stun::BuildChannelData(0x4000, payload.data(), payload.size());
  ASSERT_TRUE(stun::IsChannelData(bytes.data(), bytes.size()));
  const auto parsed = stun::ParseChannelData(bytes.data(), bytes.size());
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(parsed->first, 0x4000);
  EXPECT_EQ(std::vector<std::uint8_t>(bytes.begin() + parsed->second.first,
                bytes.begin() + parsed->second.first + parsed->second.second),
      payload);
}

TEST(VkTurnCredentials, ExtractCallId) {
  EXPECT_EQ(
      vk_turn::ExtractCallId("https://vk.com/call/join/AbC-12_x"), "AbC-12_x");
  EXPECT_EQ(vk_turn::ExtractCallId(" vk.ru/call/join/abc?foo=1 "), "abc");
  EXPECT_EQ(vk_turn::ExtractCallId("https://vk.com/call/join/abc/"), "abc");
  EXPECT_EQ(vk_turn::ExtractCallId("abcDEF123"), "abcDEF123");
  EXPECT_EQ(vk_turn::ExtractCallId("https://example.com/abc"), "");
  EXPECT_EQ(vk_turn::ExtractCallId("bad id"), "");
  EXPECT_EQ(vk_turn::ExtractCallId(""), "");
}

TEST(VkTurnCredentials, ParseTurnServer) {
  const auto json = nlohmann::json::parse(R"({
    "turn_server": {
      "username": "1700000000:user",
      "credential": "secret",
      "urls": ["turn:155.212.1.1:19302?transport=udp",
               "turn:155.212.1.1:19302?transport=tcp",
               "turns:155.212.1.2:443?transport=tcp",
               "turn:155.212.1.3"]
    }
  })");
  const auto creds = vk_turn::ParseTurnServer(json);
  ASSERT_TRUE(creds.has_value());
  EXPECT_EQ(creds->username, "1700000000:user");
  EXPECT_EQ(creds->password, "secret");
  EXPECT_EQ(creds->servers,
      (std::vector<std::string>{"155.212.1.1:19302", "155.212.1.3:3478"}));

  EXPECT_FALSE(vk_turn::ParseTurnServer(
      nlohmann::json::parse(R"({"error_code": 1, "error_msg": "bad"})"))
                   .has_value());
}

TEST(VkTurnKcpFrames, CloseFrameRoundTrip) {
  const auto frame = vk_turn::BuildCloseFrame(0xDEADBEEF);
  EXPECT_EQ(vk_turn::CloseFrameConv(frame.data(), frame.size()), 0xDEADBEEF);
  EXPECT_EQ(vk_turn::KcpFrameConv(frame.data(), frame.size()), 0U);
}

TEST(VkTurnKcpFrames, DetectsNewConversation) {
  // kFrameKcp + KCP header: conv=7 (LE), cmd=81 (push), sn=0
  std::vector<std::uint8_t> frame(1 + 24, 0);
  frame[0] = vk_turn::kFrameKcp;
  frame[1] = 7;
  frame[5] = 81;
  EXPECT_EQ(vk_turn::KcpFrameConv(frame.data(), frame.size()), 7U);
  EXPECT_TRUE(vk_turn::KcpFrameOpensConversation(frame.data(), frame.size()));
  EXPECT_FALSE(vk_turn::KcpFrameAcknowledgesData(frame.data(), frame.size()));
  frame[13] = 1;  // sn=1: not the first segment
  EXPECT_FALSE(vk_turn::KcpFrameOpensConversation(frame.data(), frame.size()));

  // sn=0 retransmitted behind another segment in the same datagram
  std::vector<std::uint8_t> second(24, 0);
  second[0] = 7;
  second[4] = 81;
  frame.insert(frame.end(), second.begin(), second.end());
  EXPECT_TRUE(vk_turn::KcpFrameOpensConversation(frame.data(), frame.size()));

  frame[17] = 3;  // una=3: the sender has received data from the receiver
  EXPECT_TRUE(vk_turn::KcpFrameAcknowledgesData(frame.data(), frame.size()));
}
