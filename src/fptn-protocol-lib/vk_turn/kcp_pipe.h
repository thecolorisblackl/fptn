/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

struct IKCPCB;

namespace fptn::protocol::vk_turn {

// Datagram layout shared by the client tunnel and the server gateway:
//   [kFrameKcp][KCP segments...]   - data of a KCP conversation
//   [kFrameClose][conv, 4 bytes BE] - the sender closed the conversation
constexpr std::uint8_t kFrameKcp = 0x01;
constexpr std::uint8_t kFrameClose = 0x02;
constexpr std::size_t kKcpMtu = 1200;

// Conversation id of a kFrameKcp datagram, 0 when malformed.
std::uint32_t KcpFrameConv(const std::uint8_t* data, std::size_t size);
// True when the datagram carries the first data segment of a conversation
// (a new connection).
bool KcpFrameOpensConversation(const std::uint8_t* data, std::size_t size);
// True when the sender has already received data of this conversation, i.e.
// the receiver must have known it (and lost it, e.g. after a restart).
bool KcpFrameAcknowledgesData(const std::uint8_t* data, std::size_t size);
std::vector<std::uint8_t> BuildCloseFrame(std::uint32_t conv);
// Conversation id of a kFrameClose datagram, 0 when malformed.
std::uint32_t CloseFrameConv(const std::uint8_t* data, std::size_t size);

std::uint32_t KcpClockMs();

// Carries one TCP connection over a KCP conversation. Single-threaded: every
// method runs on the io_context of the socket, and the owner calls Tick()
// every few milliseconds.
class KcpPipe final : public std::enable_shared_from_this<KcpPipe> {
 public:
  using SendDatagram =
      std::function<void(const std::uint8_t* data, std::size_t size)>;

  KcpPipe(boost::asio::ip::tcp::socket socket,
      std::uint32_t conv,
      SendDatagram send);
  ~KcpPipe();

  KcpPipe(const KcpPipe&) = delete;
  KcpPipe& operator=(const KcpPipe&) = delete;

  // Starts pumping once the TCP socket is connected.
  void Start();
  // A kFrameKcp datagram of this conversation arrived.
  void Input(const std::uint8_t* data, std::size_t size);
  // The peer sent kFrameClose.
  void OnPeerClosed();
  void Tick();
  // Drops the connection immediately.
  void Close();

  bool IsFinished() const { return finished_; }
  std::uint32_t Conv() const { return conv_; }
  boost::asio::ip::tcp::socket& Socket() { return socket_; }

 private:
  static int Output(const char* buf, int len, IKCPCB* kcp, void* user);

  void ReadTcp();
  void DrainKcp();
  void WriteTcp();
  void Finish();

  boost::asio::ip::tcp::socket socket_;
  const std::uint32_t conv_;
  SendDatagram send_;
  IKCPCB* kcp_ = nullptr;

  bool started_ = false;
  bool reading_ = false;
  bool writing_ = false;
  bool tcp_eof_ = false;
  bool peer_closed_ = false;
  bool finished_ = false;
  std::chrono::steady_clock::time_point last_activity_;
  std::chrono::steady_clock::time_point eof_time_;

  std::deque<std::vector<std::uint8_t>> write_queue_;
  std::size_t write_queue_bytes_ = 0;
  std::array<std::uint8_t, 16 * 1024> read_buffer_{};
  std::vector<std::uint8_t> datagram_;
};

using KcpPipeSPtr = std::shared_ptr<KcpPipe>;

}  // namespace fptn::protocol::vk_turn
