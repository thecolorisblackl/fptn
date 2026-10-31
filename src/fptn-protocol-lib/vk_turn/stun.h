/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/ip/udp.hpp>

// Minimal STUN/TURN (RFC 5389 / RFC 5766) codec: just what a TURN client
// needs to allocate a relay, bind a channel and exchange ChannelData.
namespace fptn::protocol::vk_turn::stun {

constexpr std::uint32_t kMagicCookie = 0x2112A442;
constexpr std::size_t kHeaderSize = 20;

enum Method : std::uint16_t {
  kBinding = 0x0001,
  kAllocate = 0x0003,
  kRefresh = 0x0004,
  kCreatePermission = 0x0008,
  kChannelBind = 0x0009,
};

enum Class : std::uint16_t {
  kRequest = 0x0000,
  kIndication = 0x0010,
  kSuccess = 0x0100,
  kError = 0x0110,
};

enum Attribute : std::uint16_t {
  kUsername = 0x0006,
  kMessageIntegrity = 0x0008,
  kErrorCode = 0x0009,
  kChannelNumber = 0x000C,
  kLifetime = 0x000D,
  kXorPeerAddress = 0x0012,
  kRealm = 0x0014,
  kNonce = 0x0015,
  kXorRelayedAddress = 0x0016,
  kRequestedTransport = 0x0019,
  kXorMappedAddress = 0x0020,
  kFingerprint = 0x8028,
};

using TransactionId = std::array<std::uint8_t, 12>;

TransactionId NewTransactionId();

// MD5(username ":" realm ":" password), the long-term credential key.
std::string LongTermKey(const std::string& username,
    const std::string& realm,
    const std::string& password);

class MessageBuilder final {
 public:
  MessageBuilder(std::uint16_t method,
      std::uint16_t message_class,
      const TransactionId& transaction_id);

  void AddAttribute(
      std::uint16_t type, const std::uint8_t* data, std::size_t size);
  void AddString(std::uint16_t type, const std::string& value);
  void AddUint32(std::uint16_t type, std::uint32_t value);
  void AddXorAddress(
      std::uint16_t type, const boost::asio::ip::udp::endpoint& endpoint);

  // Empty key: no MESSAGE-INTEGRITY. FINGERPRINT is always appended, as
  // browsers do.
  std::vector<std::uint8_t> Build(const std::string& integrity_key) const;

 private:
  std::vector<std::uint8_t> buffer_;
  TransactionId transaction_id_;
};

struct Message final {
  std::uint16_t method = 0;
  std::uint16_t message_class = 0;
  TransactionId transaction_id{};
  std::vector<std::pair<std::uint16_t, std::vector<std::uint8_t>>> attributes;

  const std::vector<std::uint8_t>* Find(std::uint16_t type) const;
  std::optional<std::string> GetString(std::uint16_t type) const;
  std::optional<std::uint32_t> GetUint32(std::uint16_t type) const;
  std::optional<boost::asio::ip::udp::endpoint> GetXorAddress(
      std::uint16_t type) const;
  // Code of the ERROR-CODE attribute (e.g. 401), 0 when absent.
  int ErrorCode() const;
};

std::optional<Message> Parse(const std::uint8_t* data, std::size_t size);

// ChannelData (RFC 5766 section 11.4): channel numbers 0x4000..0x7FFF.
bool IsChannelData(const std::uint8_t* data, std::size_t size);

std::vector<std::uint8_t> BuildChannelData(
    std::uint16_t channel, const std::uint8_t* data, std::size_t size);

// Returns the channel number and the payload (offset, size) inside `data`.
std::optional<std::pair<std::uint16_t, std::pair<std::size_t, std::size_t>>>
ParseChannelData(const std::uint8_t* data, std::size_t size);

}  // namespace fptn::protocol::vk_turn::stun
