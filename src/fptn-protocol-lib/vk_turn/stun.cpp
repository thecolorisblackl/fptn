/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/vk_turn/stun.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <openssl/evp.h>   // NOLINT(build/include_order)
#include <openssl/hmac.h>  // NOLINT(build/include_order)
#include <openssl/md5.h>   // NOLINT(build/include_order)
#include <openssl/rand.h>  // NOLINT(build/include_order)
#include <zlib.h>          // NOLINT(build/include_order)

namespace fptn::protocol::vk_turn::stun {

namespace {

constexpr std::uint32_t kFingerprintXor = 0x5354554E;
constexpr std::size_t kIntegritySize = 20;

void PutUint16(std::vector<std::uint8_t>& buf, std::uint16_t value) {
  buf.push_back(static_cast<std::uint8_t>(value >> 8));
  buf.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void PutUint32(std::vector<std::uint8_t>& buf, std::uint32_t value) {
  PutUint16(buf, static_cast<std::uint16_t>(value >> 16));
  PutUint16(buf, static_cast<std::uint16_t>(value & 0xFFFF));
}

std::uint16_t ReadUint16(const std::uint8_t* data) {
  return static_cast<std::uint16_t>((data[0] << 8) | data[1]);
}

std::uint32_t ReadUint32(const std::uint8_t* data) {
  return (static_cast<std::uint32_t>(ReadUint16(data)) << 16) |
         ReadUint16(data + 2);
}

void SetLength(std::vector<std::uint8_t>& buf, std::size_t body_size) {
  buf[2] = static_cast<std::uint8_t>(body_size >> 8);
  buf[3] = static_cast<std::uint8_t>(body_size & 0xFF);
}

void AppendAttribute(std::vector<std::uint8_t>& buf,
    std::uint16_t type,
    const std::uint8_t* data,
    std::size_t size) {
  PutUint16(buf, type);
  PutUint16(buf, static_cast<std::uint16_t>(size));
  buf.insert(buf.end(), data, data + size);
  while (buf.size() % 4 != 0) {
    buf.push_back(0);
  }
}

}  // namespace

TransactionId NewTransactionId() {
  TransactionId id{};
  RAND_bytes(id.data(), static_cast<int>(id.size()));
  return id;
}

std::string LongTermKey(const std::string& username,
    const std::string& realm,
    const std::string& password) {
  const std::string input = username + ":" + realm + ":" + password;
  std::array<std::uint8_t, MD5_DIGEST_LENGTH> digest{};
  MD5(reinterpret_cast<const std::uint8_t*>(input.data()), input.size(),
      digest.data());
  return {digest.begin(), digest.end()};
}

MessageBuilder::MessageBuilder(std::uint16_t method,
    std::uint16_t message_class,
    const TransactionId& transaction_id)
    : transaction_id_(transaction_id) {
  buffer_.reserve(256);
  // Methods used here fit in the low 4 bits, so no bit interleaving needed.
  PutUint16(buffer_, static_cast<std::uint16_t>(method | message_class));
  PutUint16(buffer_, 0);
  PutUint32(buffer_, kMagicCookie);
  buffer_.insert(buffer_.end(), transaction_id.begin(), transaction_id.end());
}

void MessageBuilder::AddAttribute(
    std::uint16_t type, const std::uint8_t* data, std::size_t size) {
  AppendAttribute(buffer_, type, data, size);
}

void MessageBuilder::AddString(std::uint16_t type, const std::string& value) {
  AddAttribute(
      type, reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
}

void MessageBuilder::AddUint32(std::uint16_t type, std::uint32_t value) {
  std::vector<std::uint8_t> data;
  PutUint32(data, value);
  AddAttribute(type, data.data(), data.size());
}

void MessageBuilder::AddXorAddress(
    std::uint16_t type, const boost::asio::ip::udp::endpoint& endpoint) {
  std::vector<std::uint8_t> data;
  data.push_back(0);
  const auto port =
      static_cast<std::uint16_t>(endpoint.port() ^ (kMagicCookie >> 16));
  if (endpoint.address().is_v4()) {
    data.push_back(0x01);
    PutUint16(data, port);
    PutUint32(data, endpoint.address().to_v4().to_uint() ^ kMagicCookie);
  } else {
    data.push_back(0x02);
    PutUint16(data, port);
    const auto bytes = endpoint.address().to_v6().to_bytes();
    std::array<std::uint8_t, 16> mask{};
    mask[0] = static_cast<std::uint8_t>(kMagicCookie >> 24);
    mask[1] = static_cast<std::uint8_t>((kMagicCookie >> 16) & 0xFF);
    mask[2] = static_cast<std::uint8_t>((kMagicCookie >> 8) & 0xFF);
    mask[3] = static_cast<std::uint8_t>(kMagicCookie & 0xFF);
    std::copy(transaction_id_.begin(), transaction_id_.end(), mask.begin() + 4);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      data.push_back(bytes[i] ^ mask[i]);
    }
  }
  AddAttribute(type, data.data(), data.size());
}

std::vector<std::uint8_t> MessageBuilder::Build(
    const std::string& integrity_key) const {
  std::vector<std::uint8_t> out = buffer_;
  if (!integrity_key.empty()) {
    // The length must already count the MESSAGE-INTEGRITY attribute.
    SetLength(out, out.size() - kHeaderSize + 4 + kIntegritySize);
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> hmac{};
    unsigned int hmac_size = 0;
    HMAC(EVP_sha1(), integrity_key.data(),
        static_cast<int>(integrity_key.size()), out.data(), out.size(),
        hmac.data(), &hmac_size);
    AppendAttribute(out, kMessageIntegrity, hmac.data(), kIntegritySize);
  }
  SetLength(out, out.size() - kHeaderSize + 8);
  const auto crc = static_cast<std::uint32_t>(
      crc32(0L, out.data(), static_cast<uInt>(out.size())));
  std::vector<std::uint8_t> fingerprint;
  PutUint32(fingerprint, crc ^ kFingerprintXor);
  AppendAttribute(out, kFingerprint, fingerprint.data(), fingerprint.size());
  return out;
}

const std::vector<std::uint8_t>* Message::Find(std::uint16_t type) const {
  for (const auto& [attr_type, value] : attributes) {
    if (attr_type == type) {
      return &value;
    }
  }
  return nullptr;
}

std::optional<std::string> Message::GetString(std::uint16_t type) const {
  const auto* value = Find(type);
  if (!value) {
    return std::nullopt;
  }
  return std::string(value->begin(), value->end());
}

std::optional<std::uint32_t> Message::GetUint32(std::uint16_t type) const {
  const auto* value = Find(type);
  if (!value || value->size() != 4) {
    return std::nullopt;
  }
  return ReadUint32(value->data());
}

std::optional<boost::asio::ip::udp::endpoint> Message::GetXorAddress(
    std::uint16_t type) const {
  const auto* value = Find(type);
  if (!value || value->size() < 8) {
    return std::nullopt;
  }
  const std::uint8_t* data = value->data();
  const auto port =
      static_cast<std::uint16_t>(ReadUint16(data + 2) ^ (kMagicCookie >> 16));
  if (data[1] == 0x01) {
    const boost::asio::ip::address_v4 address(
        ReadUint32(data + 4) ^ kMagicCookie);
    return boost::asio::ip::udp::endpoint(address, port);
  }
  if (data[1] == 0x02 && value->size() >= 20) {
    boost::asio::ip::address_v6::bytes_type bytes{};
    std::array<std::uint8_t, 16> mask{};
    mask[0] = static_cast<std::uint8_t>(kMagicCookie >> 24);
    mask[1] = static_cast<std::uint8_t>((kMagicCookie >> 16) & 0xFF);
    mask[2] = static_cast<std::uint8_t>((kMagicCookie >> 8) & 0xFF);
    mask[3] = static_cast<std::uint8_t>(kMagicCookie & 0xFF);
    std::copy(transaction_id.begin(), transaction_id.end(), mask.begin() + 4);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      bytes[i] = data[4 + i] ^ mask[i];
    }
    return boost::asio::ip::udp::endpoint(
        boost::asio::ip::address_v6(bytes), port);
  }
  return std::nullopt;
}

int Message::ErrorCode() const {
  const auto* value = Find(kErrorCode);
  if (!value || value->size() < 4) {
    return 0;
  }
  return ((*value)[2] & 0x07) * 100 + (*value)[3];
}

std::optional<Message> Parse(const std::uint8_t* data, std::size_t size) {
  if (size < kHeaderSize || (data[0] & 0xC0) != 0 ||
      ReadUint32(data + 4) != kMagicCookie) {
    return std::nullopt;
  }
  const std::size_t length = ReadUint16(data + 2);
  if (length % 4 != 0 || kHeaderSize + length > size) {
    return std::nullopt;
  }
  const std::uint16_t type = ReadUint16(data);
  Message msg;
  msg.message_class = static_cast<std::uint16_t>(type & 0x0110);
  msg.method = static_cast<std::uint16_t>(
      (type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2));
  std::copy(data + 8, data + kHeaderSize, msg.transaction_id.begin());

  std::size_t offset = kHeaderSize;
  const std::size_t end = kHeaderSize + length;
  while (offset + 4 <= end) {
    const std::uint16_t attr_type = ReadUint16(data + offset);
    const std::size_t attr_size = ReadUint16(data + offset + 2);
    offset += 4;
    if (offset + attr_size > end) {
      return std::nullopt;
    }
    msg.attributes.emplace_back(attr_type,
        std::vector<std::uint8_t>(data + offset, data + offset + attr_size));
    offset += (attr_size + 3) & ~static_cast<std::size_t>(3);
  }
  return msg;
}

bool IsChannelData(const std::uint8_t* data, std::size_t size) {
  return size >= 4 && (data[0] & 0xC0) == 0x40;
}

std::vector<std::uint8_t> BuildChannelData(
    std::uint16_t channel, const std::uint8_t* data, std::size_t size) {
  std::vector<std::uint8_t> out;
  out.reserve(4 + size);
  PutUint16(out, channel);
  PutUint16(out, static_cast<std::uint16_t>(size));
  out.insert(out.end(), data, data + size);
  return out;
}

std::optional<std::pair<std::uint16_t, std::pair<std::size_t, std::size_t>>>
ParseChannelData(const std::uint8_t* data, std::size_t size) {
  if (!IsChannelData(data, size)) {
    return std::nullopt;
  }
  const std::size_t length = ReadUint16(data + 2);
  if (4 + length > size) {
    return std::nullopt;
  }
  return std::make_pair(
      ReadUint16(data), std::make_pair(std::size_t{4}, length));
}

}  // namespace fptn::protocol::vk_turn::stun
