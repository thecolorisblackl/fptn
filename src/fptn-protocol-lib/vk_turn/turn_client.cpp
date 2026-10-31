/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/vk_turn/turn_client.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::protocol::vk_turn {

namespace {

constexpr std::uint16_t kChannelNumber = 0x4000;
constexpr std::uint32_t kRequestedLifetimeSec = 600;
constexpr std::uint32_t kTransportUdp = 17U << 24;
constexpr int kMaxAttempts = 5;
constexpr int kMaxAuthRetries = 2;
// A channel binding lives 10 minutes, its permission 5: refresh both early.
constexpr auto kChannelRefreshInterval = std::chrono::seconds(240);
// A relay that has been silent this long is probed with a Refresh request:
// no answer means the allocation is gone.
constexpr auto kLivenessInterval = std::chrono::seconds(5);

std::string ErrorText(const stun::Message& msg) {
  const auto* value = msg.Find(stun::kErrorCode);
  std::string reason;
  if (value && value->size() > 4) {
    reason.assign(value->begin() + 4, value->end());
  }
  return fmt::format("{} {}", msg.ErrorCode(), reason);
}

}  // namespace

TurnClient::TurnClient(boost::asio::io_context& ioc,
    boost::asio::ip::udp::endpoint turn_server,
    Credentials credentials,
    boost::asio::ip::udp::endpoint peer,
    OnDataCallback on_data,
    OnStateCallback on_state,
    OnSocketOpenedCallback on_socket_opened)
    : ioc_(ioc),
      socket_(ioc),
      turn_server_(std::move(turn_server)),
      credentials_(std::move(credentials)),
      peer_(std::move(peer)),
      on_data_(std::move(on_data)),
      on_state_(std::move(on_state)),
      on_socket_opened_(std::move(on_socket_opened)),
      refresh_timer_(ioc),
      channel_timer_(ioc),
      liveness_timer_(ioc) {}  // NOLINT(whitespace/indent_namespace)

void TurnClient::Start() {
  boost::system::error_code ec;
  socket_.open(turn_server_.protocol(), ec);
  if (!ec) {
    socket_.connect(turn_server_, ec);
  }
  if (!ec) {
    socket_.non_blocking(true, ec);
  }
  if (ec) {
    Fail(fmt::format("TURN socket error: {}", ec.message()), false);
    return;
  }
  if (on_socket_opened_) {
    on_socket_opened_(static_cast<int>(socket_.native_handle()));
  }
  Receive();
  Allocate();
}

void TurnClient::Stop() {
  if (stopped_) {
    return;
  }
  if (ready_) {
    // Release the allocation right away instead of letting it expire.
    stun::MessageBuilder builder(
        stun::kRefresh, stun::kRequest, stun::NewTransactionId());
    builder.AddUint32(stun::kLifetime, 0);
    builder.AddString(stun::kUsername, credentials_.username);
    builder.AddString(stun::kRealm, realm_);
    builder.AddString(stun::kNonce, nonce_);
    const auto bytes = builder.Build(key_);
    boost::system::error_code ec;
    socket_.send(boost::asio::buffer(bytes), 0, ec);
  }
  stopped_ = true;
  ready_ = false;
  for (auto& [id, req] : pending_) {
    req->timer->cancel();
  }
  pending_.clear();
  refresh_timer_.cancel();
  channel_timer_.cancel();
  liveness_timer_.cancel();
  boost::system::error_code ec;
  socket_.close(ec);
}

void TurnClient::Send(const std::uint8_t* data, std::size_t size) {
  if (!ready_) {
    return;
  }
  const auto packet = stun::BuildChannelData(kChannelNumber, data, size);
  boost::system::error_code ec;
  // UDP semantics: a full socket buffer drops the datagram, KCP resends it.
  socket_.send(boost::asio::buffer(packet), 0, ec);
}

void TurnClient::SendRequest(
    std::uint16_t method, AttributesFiller fill, ResponseHandler on_success) {
  auto req = std::make_shared<Request>();
  req->method = method;
  req->fill = std::move(fill);
  req->on_success = std::move(on_success);
  req->timer = std::make_unique<boost::asio::steady_timer>(ioc_);
  Transmit(stun::NewTransactionId(), std::move(req));
}

void TurnClient::Transmit(
    const stun::TransactionId& id, std::shared_ptr<Request> req) {
  stun::MessageBuilder builder(req->method, stun::kRequest, id);
  req->fill(builder);
  if (!nonce_.empty()) {
    builder.AddString(stun::kUsername, credentials_.username);
    builder.AddString(stun::kRealm, realm_);
    builder.AddString(stun::kNonce, nonce_);
  }
  req->bytes = builder.Build(nonce_.empty() ? std::string() : key_);
  req->attempts = 0;
  pending_[id] = req;
  SendAttempt(id, std::move(req));
}

void TurnClient::SendAttempt(
    const stun::TransactionId& id, const std::shared_ptr<Request>& req) {
  if (stopped_ || pending_.find(id) == pending_.end()) {
    return;
  }
  if (req->attempts >= kMaxAttempts) {
    pending_.erase(id);
    Fail("TURN server does not respond", false);
    return;
  }
  boost::system::error_code ec;
  socket_.send(boost::asio::buffer(req->bytes), 0, ec);
  // RFC 5389 retransmission: 500ms, then doubling
  const auto timeout = std::chrono::milliseconds(500 << req->attempts);
  ++req->attempts;
  req->timer->expires_after(timeout);
  auto self = shared_from_this();
  req->timer->async_wait(
      [this, self, id, req](boost::system::error_code wait_ec) {
        if (!wait_ec) {
          SendAttempt(id, req);
        }
      });
}

void TurnClient::Receive() {
  auto self = shared_from_this();
  socket_.async_receive(boost::asio::buffer(recv_buffer_),
      [this, self](boost::system::error_code ec, std::size_t size) {
        if (stopped_) {
          return;
        }
        if (ec) {
          if (ec == boost::asio::error::would_block ||
              ec == boost::asio::error::try_again ||
              ec == boost::asio::error::connection_refused) {
            Receive();
            return;
          }
          Fail(fmt::format("TURN receive error: {}", ec.message()), false);
          return;
        }
        last_receive_ = std::chrono::steady_clock::now();
        const auto* data = recv_buffer_.data();
        if (stun::IsChannelData(data, size)) {
          const auto parsed = stun::ParseChannelData(data, size);
          if (parsed && parsed->first == kChannelNumber && on_data_) {
            on_data_(data + parsed->second.first, parsed->second.second);
          }
        } else if (const auto msg = stun::Parse(data, size)) {
          HandleStun(*msg);
        }
        if (!stopped_) {
          Receive();
        }
      });
}

void TurnClient::HandleStun(const stun::Message& msg) {
  if (msg.message_class != stun::kSuccess &&
      msg.message_class != stun::kError) {
    return;  // indications are not used: data goes over the channel
  }
  const auto it = pending_.find(msg.transaction_id);
  if (it == pending_.end()) {
    return;
  }
  auto req = it->second;
  req->timer->cancel();
  pending_.erase(it);

  if (msg.message_class == stun::kSuccess) {
    req->on_success(msg);
    return;
  }

  const int code = msg.ErrorCode();
  if ((code == 401 || code == 438) && req->auth_retries < kMaxAuthRetries) {
    const auto realm = msg.GetString(stun::kRealm);
    const auto nonce = msg.GetString(stun::kNonce);
    if (nonce) {
      if (realm) {
        realm_ = *realm;
      }
      nonce_ = *nonce;
      key_ = stun::LongTermKey(
          credentials_.username, realm_, credentials_.password);
      ++req->auth_retries;
      Transmit(stun::NewTransactionId(), req);
      return;
    }
  }
  // An authenticated request rejected with 401/441 (or 400 by some servers)
  // means the credentials are wrong or expired
  const bool auth_error =
      code == 401 || code == 441 || (code == 400 && req->auth_retries > 0);
  Fail(
      fmt::format("TURN request {:#x} failed: {}", req->method, ErrorText(msg)),
      auth_error);
}

void TurnClient::Allocate() {
  auto self = shared_from_this();
  SendRequest(
      stun::kAllocate,
      [](stun::MessageBuilder& builder) {
        builder.AddUint32(stun::kRequestedTransport, kTransportUdp);
        builder.AddUint32(stun::kLifetime, kRequestedLifetimeSec);
      },
      [this, self](const stun::Message& msg) {
        lifetime_sec_ = msg.GetUint32(stun::kLifetime).value_or(600);
        const auto relayed = msg.GetXorAddress(stun::kXorRelayedAddress);
        SPDLOG_INFO("TURN allocation is ready: relay={} lifetime={}s",
            relayed ? relayed->address().to_string() : "?", lifetime_sec_);
        BindChannel();
      });
}

void TurnClient::BindChannel() {
  auto self = shared_from_this();
  SendRequest(
      stun::kChannelBind,
      [this](stun::MessageBuilder& builder) {
        builder.AddUint32(stun::kChannelNumber,
            static_cast<std::uint32_t>(kChannelNumber) << 16);
        builder.AddXorAddress(stun::kXorPeerAddress, peer_);
      },
      [this, self](const stun::Message&) {
        if (!ready_) {
          ready_ = true;
          ScheduleRefresh();
          ScheduleChannelRefresh();
          ScheduleLivenessCheck();
          if (on_state_) {
            on_state_(true, false, {});
          }
        }
      });
}

void TurnClient::Refresh(std::uint32_t lifetime) {
  auto self = shared_from_this();
  SendRequest(
      stun::kRefresh,
      [lifetime](stun::MessageBuilder& builder) {
        builder.AddUint32(stun::kLifetime, lifetime);
      },
      [this, self](const stun::Message& msg) {
        lifetime_sec_ = msg.GetUint32(stun::kLifetime).value_or(lifetime_sec_);
      });
}

void TurnClient::ScheduleRefresh() {
  auto self = shared_from_this();
  const auto refresh_after =
      std::chrono::seconds(std::max<std::uint32_t>(30, lifetime_sec_ - 60));
  refresh_timer_.expires_after(refresh_after);
  refresh_timer_.async_wait([this, self](boost::system::error_code ec) {
    if (ec || stopped_) {
      return;
    }
    Refresh(kRequestedLifetimeSec);
    ScheduleRefresh();
  });
}

void TurnClient::ScheduleChannelRefresh() {
  auto self = shared_from_this();
  channel_timer_.expires_after(kChannelRefreshInterval);
  channel_timer_.async_wait([this, self](boost::system::error_code ec) {
    if (ec || stopped_) {
      return;
    }
    // Re-binding the same channel refreshes it and its permission
    BindChannel();
    ScheduleChannelRefresh();
  });
}

void TurnClient::ScheduleLivenessCheck() {
  auto self = shared_from_this();
  liveness_timer_.expires_after(kLivenessInterval);
  liveness_timer_.async_wait([this, self](boost::system::error_code ec) {
    if (ec || stopped_) {
      return;
    }
    if (std::chrono::steady_clock::now() - last_receive_ >= kLivenessInterval) {
      Refresh(kRequestedLifetimeSec);  // fails the client if unanswered
    }
    ScheduleLivenessCheck();
  });
}

void TurnClient::Fail(const std::string& error, bool auth_error) {
  if (stopped_) {
    return;
  }
  SPDLOG_WARN("TURN allocation failed: {}", error);
  ready_ = false;
  auto on_state = std::move(on_state_);
  Stop();
  if (on_state) {
    on_state(false, auth_error, error);
  }
}

}  // namespace fptn::protocol::vk_turn
