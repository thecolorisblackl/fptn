/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <thread>
#include <unordered_map>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "fptn-protocol-lib/vk_turn/kcp_pipe.h"

namespace fptn::vk_turn {

// Server side of the VK calls TURN bypass: clients reach this UDP port
// through the VK TURN relays. Each KCP conversation is turned into a TCP
// connection to the local fptn HTTPS port, so the rest of the server sees an
// ordinary client connection.
class UdpGateway final {
 public:
  UdpGateway(std::uint16_t udp_port, std::uint16_t backend_port);
  ~UdpGateway();

  UdpGateway(const UdpGateway&) = delete;
  UdpGateway& operator=(const UdpGateway&) = delete;

  bool Start();
  void Stop();

 private:
  struct Conversation {
    fptn::protocol::vk_turn::KcpPipeSPtr pipe;
    boost::asio::ip::udp::endpoint peer;
  };

  void Receive();
  void Tick();
  void HandleDatagram(std::size_t size);
  void OpenConversation(std::uint32_t conv, std::size_t size);
  void SendTo(const boost::asio::ip::udp::endpoint& peer,
      const std::uint8_t* data,
      std::size_t size);

  const std::uint16_t udp_port_;
  const std::uint16_t backend_port_;

  boost::asio::io_context ioc_;
  boost::asio::ip::udp::socket socket_;
  boost::asio::steady_timer tick_timer_;
  std::thread thread_;

  std::unordered_map<std::uint32_t, Conversation> conversations_;
  std::array<std::uint8_t, 65536> buffer_{};
  boost::asio::ip::udp::endpoint sender_;
};

using UdpGatewayPtr = std::unique_ptr<UdpGateway>;

}  // namespace fptn::vk_turn
