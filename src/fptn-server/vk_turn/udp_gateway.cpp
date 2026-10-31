/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vk_turn/udp_gateway.h"

#include <memory>
#include <utility>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::vk_turn {

namespace {
using fptn::protocol::vk_turn::BuildCloseFrame;
using fptn::protocol::vk_turn::CloseFrameConv;
using fptn::protocol::vk_turn::KcpFrameAcknowledgesData;
using fptn::protocol::vk_turn::KcpFrameConv;
using fptn::protocol::vk_turn::KcpFrameOpensConversation;
using fptn::protocol::vk_turn::KcpPipe;
using fptn::protocol::vk_turn::kFrameClose;
using fptn::protocol::vk_turn::kFrameKcp;

constexpr auto kTickInterval = std::chrono::milliseconds(10);
constexpr std::size_t kMaxConversations = 4096;
}  // namespace

UdpGateway::UdpGateway(std::uint16_t udp_port, std::uint16_t backend_port)
    : udp_port_(udp_port),
      backend_port_(backend_port),
      socket_(ioc_),
      tick_timer_(ioc_) {}  // NOLINT(whitespace/indent_namespace)

// NOLINTNEXTLINE(bugprone-exception-escape)
UdpGateway::~UdpGateway() { Stop(); }

bool UdpGateway::Start() {
  boost::system::error_code ec;
  socket_.open(boost::asio::ip::udp::v4(), ec);
  if (!ec) {
    socket_.bind(
        boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), udp_port_),
        ec);
  }
  if (!ec) {
    socket_.non_blocking(true, ec);
  }
  if (ec) {
    SPDLOG_ERROR("VK TURN gateway: cannot listen on UDP port {}: {}", udp_port_,
        ec.message());
    return false;
  }
  boost::asio::post(ioc_, [this]() {
    Receive();
    Tick();
  });
  thread_ = std::thread([this]() { ioc_.run(); });
  SPDLOG_INFO("VK TURN gateway listens on UDP port {}", udp_port_);
  return true;
}

void UdpGateway::Stop() {
  if (!thread_.joinable()) {
    return;
  }
  boost::asio::post(ioc_, [this]() {
    boost::system::error_code ec;
    socket_.close(ec);
    tick_timer_.cancel();
    for (auto& [conv, conversation] : conversations_) {
      conversation.pipe->Close();
    }
    conversations_.clear();
    ioc_.stop();
  });
  thread_.join();
}

void UdpGateway::Receive() {
  socket_.async_receive_from(boost::asio::buffer(buffer_), sender_,
      [this](boost::system::error_code ec, std::size_t size) {
        if (ec == boost::asio::error::operation_aborted) {
          return;
        }
        if (!ec) {
          HandleDatagram(size);
        }
        Receive();
      });
}

void UdpGateway::HandleDatagram(std::size_t size) {
  const std::uint8_t* data = buffer_.data();
  if (size == 0) {
    return;
  }
  if (data[0] == kFrameClose) {
    const auto it = conversations_.find(CloseFrameConv(data, size));
    if (it != conversations_.end()) {
      it->second.pipe->OnPeerClosed();
    }
    return;
  }
  if (data[0] != kFrameKcp) {
    return;
  }
  const std::uint32_t conv = KcpFrameConv(data, size);
  if (conv == 0) {
    return;
  }
  const auto it = conversations_.find(conv);
  if (it != conversations_.end()) {
    // The client may move a conversation to another relay
    it->second.peer = sender_;
    it->second.pipe->Input(data, size);
    return;
  }
  if (KcpFrameOpensConversation(data, size)) {
    OpenConversation(conv, size);
  } else if (KcpFrameAcknowledgesData(data, size)) {
    // The client got data of a conversation we do not know (e.g. after a
    // restart): tell it to drop the conversation
    const auto frame = BuildCloseFrame(conv);
    SendTo(sender_, frame.data(), frame.size());
  }
  // Otherwise the opening segment was lost: wait for its retransmission
}

void UdpGateway::OpenConversation(std::uint32_t conv, std::size_t size) {
  if (conversations_.size() >= kMaxConversations) {
    SPDLOG_WARN("VK TURN gateway: too many conversations");
    return;
  }
  auto pipe = std::make_shared<KcpPipe>(boost::asio::ip::tcp::socket(ioc_),
      conv, [this, conv](const std::uint8_t* data, std::size_t len) {
        const auto it = conversations_.find(conv);
        if (it != conversations_.end()) {
          SendTo(it->second.peer, data, len);
        }
      });
  conversations_[conv] = Conversation{pipe, sender_};
  // KCP buffers the data until the backend connection is up
  pipe->Input(buffer_.data(), size);

  const boost::asio::ip::tcp::endpoint backend(
      boost::asio::ip::address_v4::loopback(), backend_port_);
  pipe->Socket().async_connect(backend, [pipe](boost::system::error_code ec) {
    if (ec) {
      SPDLOG_WARN("VK TURN gateway: backend connect failed: {}", ec.message());
      pipe->Close();
      return;
    }
    pipe->Start();
  });
}

void UdpGateway::SendTo(const boost::asio::ip::udp::endpoint& peer,
    const std::uint8_t* data,
    std::size_t size) {
  boost::system::error_code ec;
  socket_.send_to(boost::asio::buffer(data, size), peer, 0, ec);
}

void UdpGateway::Tick() {
  for (auto it = conversations_.begin(); it != conversations_.end();) {
    it->second.pipe->Tick();
    if (it->second.pipe->IsFinished()) {
      it = conversations_.erase(it);
    } else {
      ++it;
    }
  }
  tick_timer_.expires_after(kTickInterval);
  tick_timer_.async_wait([this](boost::system::error_code ec) {
    if (!ec) {
      Tick();
    }
  });
}

}  // namespace fptn::vk_turn
