/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "fptn-protocol-lib/vk_turn/kcp_pipe.h"
#include "fptn-protocol-lib/vk_turn/turn_client.h"
#include "fptn-protocol-lib/vk_turn/vk_credentials.h"

namespace fptn::protocol::vk_turn {

// Bypass through the TURN servers of VK calls.
//
// The tunnel joins a VK call anonymously to get TURN credentials, allocates
// relays on the VK TURN servers and binds them to the UDP gateway of the fptn
// server. Locally it listens on 127.0.0.1: every TCP connection accepted there
// becomes a KCP conversation through a relay, and the server gateway turns it
// back into a TCP connection to its own HTTPS port. So the regular fptn
// client just connects to 127.0.0.1:LocalPort() instead of the server.
class VkTurnTunnel final {
 public:
  struct Config {
    std::string call_link;          // VK call link or its id
    std::string server_ip;          // fptn server
    std::uint16_t server_port = 0;  // UDP port of the server gateway
    std::size_t allocations = 3;
    CaptchaSolver captcha_solver;  // may be called from a worker thread
    TurnClient::OnSocketOpenedCallback on_socket_opened;
    // Source of the TURN credentials, FetchTurnCredentials when empty
    std::function<FetchResult(
        const std::string& call_id, const CaptchaSolver& captcha_solver)>
        fetch_credentials;
  };

  explicit VkTurnTunnel(Config config);
  ~VkTurnTunnel();

  VkTurnTunnel(const VkTurnTunnel&) = delete;
  VkTurnTunnel& operator=(const VkTurnTunnel&) = delete;

  // Blocks until a relay is ready or the attempt failed.
  bool Start(int timeout_sec = 30);
  void Stop();

  std::uint16_t LocalPort() const { return local_port_; }
  // IPv4 addresses that have to bypass the VPN tunnel: the TURN servers and
  // the VK API servers used to renew the credentials.
  std::vector<std::string> BypassAddresses() const;
  std::string LatestError() const;

 private:
  struct Slot {
    TurnClientSPtr client;
    std::string username;  // credentials the client was started with
    bool ready = false;
    int failures = 0;
    std::unique_ptr<boost::asio::steady_timer> restart_timer;
  };

  FetchResult Fetch() const;
  bool ApplyCredentials(const FetchResult& result);
  void StartSlot(std::size_t index);
  void OnSlotState(std::size_t index,
      const TurnClientSPtr& client,
      bool ready,
      bool auth_error,
      const std::string& error);
  void RenewCredentials();
  void Accept();
  void Tick();
  void HandleDatagram(const std::uint8_t* data, std::size_t size);
  void SendVia(std::uint32_t conv, const std::uint8_t* data, std::size_t size);
  bool AnySlotReady() const;
  void SetError(const std::string& error);

  const Config config_;
  const std::string call_id_;

  boost::asio::io_context ioc_;
  boost::asio::ip::tcp::acceptor acceptor_;
  boost::asio::steady_timer tick_timer_;
  std::thread io_thread_;
  std::thread renew_thread_;
  std::atomic<bool> running_{false};
  std::atomic<bool> renewing_{false};
  std::chrono::steady_clock::time_point last_renewal_;

  // io thread only
  TurnClient::Credentials credentials_;
  std::vector<boost::asio::ip::udp::endpoint> turn_servers_;
  boost::asio::ip::udp::endpoint peer_;
  std::vector<Slot> slots_;
  std::unordered_map<std::uint32_t, KcpPipeSPtr> pipes_;
  std::unordered_map<std::uint32_t, std::size_t> pipe_slot_;
  std::size_t next_slot_ = 0;

  mutable std::mutex mutex_;
  std::condition_variable state_cv_;
  std::size_t failed_slots_ = 0;
  bool any_ready_ = false;
  std::string latest_error_;
  std::set<std::string> bypass_addresses_;
  std::uint16_t local_port_ = 0;
};

using VkTurnTunnelPtr = std::unique_ptr<VkTurnTunnel>;

}  // namespace fptn::protocol::vk_turn
