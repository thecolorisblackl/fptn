/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "fptn-protocol-lib/vk_turn/stun.h"

namespace fptn::protocol::vk_turn {

// One TURN allocation over UDP with a channel bound to a single peer.
// Every method must be called from the io_context thread.
class TurnClient final : public std::enable_shared_from_this<TurnClient> {
 public:
  struct Credentials {
    std::string username;
    std::string password;
  };

  using OnDataCallback =
      std::function<void(const std::uint8_t* data, std::size_t size)>;
  // ready: the relay accepts data now. When the allocation is lost the
  // callback fires once with ready=false; auth_error tells that the
  // credentials were rejected and have to be fetched again.
  using OnStateCallback = std::function<void(
      bool ready, bool auth_error, const std::string& error)>;
  using OnSocketOpenedCallback = std::function<void(int socket_fd)>;

  TurnClient(boost::asio::io_context& ioc,
      boost::asio::ip::udp::endpoint turn_server,
      Credentials credentials,
      boost::asio::ip::udp::endpoint peer,
      OnDataCallback on_data,
      OnStateCallback on_state,
      OnSocketOpenedCallback on_socket_opened = nullptr);

  void Start();
  void Stop();
  bool IsReady() const { return ready_; }
  void Send(const std::uint8_t* data, std::size_t size);

 private:
  using ResponseHandler = std::function<void(const stun::Message&)>;
  using AttributesFiller = std::function<void(stun::MessageBuilder&)>;

  struct Request {
    std::uint16_t method = 0;
    AttributesFiller fill;
    ResponseHandler on_success;
    std::vector<std::uint8_t> bytes;
    int attempts = 0;
    int auth_retries = 0;
    std::unique_ptr<boost::asio::steady_timer> timer;
  };

  void SendRequest(
      std::uint16_t method, AttributesFiller fill, ResponseHandler on_success);
  void Transmit(const stun::TransactionId& id, std::shared_ptr<Request> req);
  void SendAttempt(
      const stun::TransactionId& id, const std::shared_ptr<Request>& req);
  void Receive();
  void HandleStun(const stun::Message& msg);
  void Allocate();
  void BindChannel();
  void Refresh(std::uint32_t lifetime);
  void ScheduleRefresh();
  void ScheduleChannelRefresh();
  void ScheduleLivenessCheck();
  void Fail(const std::string& error, bool auth_error);

  boost::asio::io_context& ioc_;
  boost::asio::ip::udp::socket socket_;
  const boost::asio::ip::udp::endpoint turn_server_;
  const Credentials credentials_;
  const boost::asio::ip::udp::endpoint peer_;
  OnDataCallback on_data_;
  OnStateCallback on_state_;
  OnSocketOpenedCallback on_socket_opened_;

  std::string realm_;
  std::string nonce_;
  std::string key_;

  bool ready_ = false;
  bool stopped_ = false;
  std::uint32_t lifetime_sec_ = 600;

  std::map<stun::TransactionId, std::shared_ptr<Request>> pending_;
  boost::asio::steady_timer refresh_timer_;
  boost::asio::steady_timer channel_timer_;
  boost::asio::steady_timer liveness_timer_;
  std::chrono::steady_clock::time_point last_receive_;
  std::array<std::uint8_t, 65536> recv_buffer_{};
};

using TurnClientSPtr = std::shared_ptr<TurnClient>;

}  // namespace fptn::protocol::vk_turn
