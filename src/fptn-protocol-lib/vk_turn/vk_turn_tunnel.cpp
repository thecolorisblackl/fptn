/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/vk_turn/vk_turn_tunnel.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>
#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::protocol::vk_turn {

namespace {
constexpr auto kTickInterval = std::chrono::milliseconds(10);
constexpr int kMaxRestartDelaySec = 30;
// Do not hammer the VK API (and the user with captchas)
constexpr auto kMinRenewalInterval = std::chrono::seconds(30);
}  // namespace

VkTurnTunnel::VkTurnTunnel(Config config)
    : config_(std::move(config)),
      call_id_(ExtractCallId(config_.call_link)),
      acceptor_(ioc_),
      tick_timer_(ioc_) {}  // NOLINT(whitespace/indent_namespace)

// NOLINTNEXTLINE(bugprone-exception-escape)
VkTurnTunnel::~VkTurnTunnel() { Stop(); }

bool VkTurnTunnel::Start(int timeout_sec) {
  if (call_id_.empty()) {
    SetError("Invalid VK call link");
    return false;
  }
  boost::system::error_code ec;
  const auto server_address =
      boost::asio::ip::make_address(config_.server_ip, ec);
  if (ec || config_.server_port == 0) {
    SetError("Invalid server address for the VK TURN tunnel");
    return false;
  }
  peer_ = boost::asio::ip::udp::endpoint(server_address, config_.server_port);

  SPDLOG_INFO("VK TURN: requesting credentials for call {}", call_id_);
  const auto fetched = Fetch();
  if (!fetched.credentials) {
    SetError("VK TURN credentials: " + fetched.error);
    return false;
  }
  if (!ApplyCredentials(fetched)) {
    return false;
  }

  acceptor_.open(boost::asio::ip::tcp::v4(), ec);
  if (!ec) {
    acceptor_.bind(boost::asio::ip::tcp::endpoint(
                       boost::asio::ip::address_v4::loopback(), 0),
        ec);
  }
  if (!ec) {
    acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
  }
  if (ec) {
    SetError("VK TURN local listener: " + ec.message());
    return false;
  }
  local_port_ = acceptor_.local_endpoint().port();

  slots_.resize(std::max<std::size_t>(1, config_.allocations));
  running_ = true;
  boost::asio::post(ioc_, [this]() {
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      StartSlot(i);
    }
    Accept();
    Tick();
  });
  io_thread_ = std::thread([this]() { ioc_.run(); });

  std::unique_lock<std::mutex> lock(mutex_);
  state_cv_.wait_for(lock, std::chrono::seconds(timeout_sec),
      [this]() { return any_ready_ || failed_slots_ >= slots_.size(); });
  if (!any_ready_) {
    if (latest_error_.empty()) {
      latest_error_ = "VK TURN relay is not ready";
    }
    lock.unlock();
    Stop();
    return false;
  }
  SPDLOG_INFO("VK TURN tunnel is listening on 127.0.0.1:{}", local_port_);
  return true;
}

void VkTurnTunnel::Stop() {
  running_ = false;
  if (io_thread_.joinable()) {
    boost::asio::post(ioc_, [this]() {
      boost::system::error_code ec;
      acceptor_.close(ec);
      tick_timer_.cancel();
      for (auto& [conv, pipe] : pipes_) {
        pipe->Close();
      }
      pipes_.clear();
      pipe_slot_.clear();
      for (auto& slot : slots_) {
        if (slot.restart_timer) {
          slot.restart_timer->cancel();
        }
        if (slot.client) {
          slot.client->Stop();
          slot.client.reset();
        }
      }
      ioc_.stop();
    });
    io_thread_.join();
  } else {
    boost::system::error_code ec;
    acceptor_.close(ec);
  }
  if (renew_thread_.joinable()) {
    renew_thread_.join();
  }
}

std::vector<std::string> VkTurnTunnel::BypassAddresses() const {
  const std::lock_guard<std::mutex> lock(mutex_);
  return {bypass_addresses_.begin(), bypass_addresses_.end()};
}

std::string VkTurnTunnel::LatestError() const {
  const std::lock_guard<std::mutex> lock(mutex_);
  return latest_error_;
}

void VkTurnTunnel::SetError(const std::string& error) {
  SPDLOG_ERROR("{}", error);
  const std::lock_guard<std::mutex> lock(mutex_);
  latest_error_ = error;
}

FetchResult VkTurnTunnel::Fetch() const {
  if (config_.fetch_credentials) {
    return config_.fetch_credentials(call_id_, config_.captcha_solver);
  }
  return FetchTurnCredentials(call_id_, config_.captcha_solver);
}

bool VkTurnTunnel::ApplyCredentials(const FetchResult& result) {
  std::vector<boost::asio::ip::udp::endpoint> servers;
  boost::asio::ip::udp::resolver resolver(ioc_);
  for (const auto& server : result.credentials->servers) {
    const auto colon = server.rfind(':');
    boost::system::error_code ec;
    const auto endpoints = resolver.resolve(boost::asio::ip::udp::v4(),
        server.substr(0, colon), server.substr(colon + 1), ec);
    if (!ec && !endpoints.empty()) {
      servers.push_back(*endpoints.begin());
    }
  }
  if (servers.empty()) {
    SetError("VK TURN: cannot resolve the TURN servers");
    return false;
  }
  SPDLOG_INFO("VK TURN: got credentials, {} TURN server(s)", servers.size());
  credentials_ = {result.credentials->username, result.credentials->password};
  turn_servers_ = std::move(servers);

  const std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& server : turn_servers_) {
    bypass_addresses_.insert(server.address().to_string());
  }
  bypass_addresses_.insert(
      result.api_addresses.begin(), result.api_addresses.end());
  return true;
}

void VkTurnTunnel::StartSlot(std::size_t index) {
  if (!running_) {
    return;
  }
  auto& slot = slots_[index];
  const auto& server = turn_servers_[index % turn_servers_.size()];
  // The state callback compares the client with the slot's current one to
  // drop notifications of clients that were already replaced.
  auto self_ref = std::make_shared<std::weak_ptr<TurnClient>>();
  slot.client = std::make_shared<TurnClient>(
      ioc_, server, credentials_, peer_,
      [this](const std::uint8_t* data, std::size_t size) {
        HandleDatagram(data, size);
      },
      [this, index, self_ref](
          bool ready, bool auth_error, const std::string& error) {
        OnSlotState(index, self_ref->lock(), ready, auth_error, error);
      },
      config_.on_socket_opened);
  *self_ref = slot.client;
  slot.username = credentials_.username;
  slot.ready = false;
  slot.client->Start();
}

void VkTurnTunnel::OnSlotState(std::size_t index,
    const TurnClientSPtr& client,
    bool ready,
    bool auth_error,
    const std::string& error) {
  auto& slot = slots_[index];
  if (!client || slot.client != client) {
    return;
  }
  if (ready) {
    slot.ready = true;
    slot.failures = 0;
    const std::lock_guard<std::mutex> lock(mutex_);
    any_ready_ = true;
    state_cv_.notify_all();
    return;
  }

  slot.ready = false;
  slot.client.reset();
  ++slot.failures;
  SetError("VK TURN relay: " + error);
  if (slot.failures == 1) {
    const std::lock_guard<std::mutex> lock(mutex_);
    ++failed_slots_;
    state_cv_.notify_all();
  }
  // Slots started with older credentials just pick up the current ones
  if (auth_error && slot.username == credentials_.username) {
    RenewCredentials();
  }
  if (!running_) {
    return;
  }
  if (!slot.restart_timer) {
    slot.restart_timer = std::make_unique<boost::asio::steady_timer>(ioc_);
  }
  slot.restart_timer->expires_after(
      std::chrono::seconds(std::min(kMaxRestartDelaySec, 2 * slot.failures)));
  slot.restart_timer->async_wait([this, index](boost::system::error_code ec) {
    if (!ec) {
      StartSlot(index);
    }
  });
}

void VkTurnTunnel::RenewCredentials() {
  const auto now = std::chrono::steady_clock::now();
  if (!running_ || now - last_renewal_ < kMinRenewalInterval ||
      renewing_.exchange(true)) {
    return;
  }
  last_renewal_ = now;
  if (renew_thread_.joinable()) {
    renew_thread_.join();  // the previous renewal has already finished
  }
  renew_thread_ = std::thread([this]() {
    SPDLOG_INFO("VK TURN: renewing credentials");
    auto fetched = Fetch();
    boost::asio::post(ioc_, [this, fetched = std::move(fetched)]() {
      if (fetched.credentials) {
        ApplyCredentials(fetched);
      } else {
        SetError("VK TURN credentials: " + fetched.error);
      }
      renewing_ = false;
    });
  });
}

void VkTurnTunnel::Accept() {
  acceptor_.async_accept([this](boost::system::error_code ec,
                             boost::asio::ip::tcp::socket socket) {
    if (ec) {
      if (running_ && ec != boost::asio::error::operation_aborted) {
        Accept();
      }
      return;
    }
    if (!AnySlotReady()) {
      SPDLOG_WARN("VK TURN: no relay is ready, dropping connection");
      boost::system::error_code close_ec;
      socket.close(close_ec);
      Accept();
      return;
    }
    std::random_device seed;
    static thread_local std::mt19937 rng(seed());
    std::uint32_t conv = 0;
    while (conv == 0 || pipes_.contains(conv)) {
      conv = static_cast<std::uint32_t>(rng());
    }
    std::size_t slot = next_slot_++ % slots_.size();
    while (!slots_[slot].ready) {
      slot = (slot + 1) % slots_.size();
    }
    auto pipe = std::make_shared<KcpPipe>(std::move(socket), conv,
        [this, conv](const std::uint8_t* data, std::size_t size) {
          SendVia(conv, data, size);
        });
    pipes_[conv] = pipe;
    pipe_slot_[conv] = slot;
    pipe->Start();
    Accept();
  });
}

void VkTurnTunnel::Tick() {
  for (auto it = pipes_.begin(); it != pipes_.end();) {
    it->second->Tick();
    if (it->second->IsFinished()) {
      pipe_slot_.erase(it->first);
      it = pipes_.erase(it);
    } else {
      ++it;
    }
  }
  if (!running_) {
    return;
  }
  tick_timer_.expires_after(kTickInterval);
  tick_timer_.async_wait([this](boost::system::error_code ec) {
    if (!ec) {
      Tick();
    }
  });
}

void VkTurnTunnel::HandleDatagram(const std::uint8_t* data, std::size_t size) {
  if (size == 0) {
    return;
  }
  if (data[0] == kFrameKcp) {
    const auto it = pipes_.find(KcpFrameConv(data, size));
    if (it != pipes_.end()) {
      it->second->Input(data, size);
    }
  } else if (data[0] == kFrameClose) {
    const auto it = pipes_.find(CloseFrameConv(data, size));
    if (it != pipes_.end()) {
      it->second->OnPeerClosed();
    }
  }
}

void VkTurnTunnel::SendVia(
    std::uint32_t conv, const std::uint8_t* data, std::size_t size) {
  const auto it = pipe_slot_.find(conv);
  if (it == pipe_slot_.end()) {
    return;
  }
  std::size_t slot = it->second;
  if (!slots_[slot].ready) {
    // The relay is gone: move the conversation to another one, the server
    // follows the new relay address.
    const auto ready = std::find_if(
        slots_.begin(), slots_.end(), [](const Slot& s) { return s.ready; });
    if (ready == slots_.end()) {
      return;
    }
    slot = static_cast<std::size_t>(std::distance(slots_.begin(), ready));
    it->second = slot;
  }
  slots_[slot].client->Send(data, size);
}

bool VkTurnTunnel::AnySlotReady() const {
  return std::any_of(
      slots_.begin(), slots_.end(), [](const Slot& s) { return s.ready; });
}

}  // namespace fptn::protocol::vk_turn
