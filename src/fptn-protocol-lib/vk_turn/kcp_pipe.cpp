/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/vk_turn/kcp_pipe.h"

#include <ikcp.h>  // NOLINT(build/include_order)
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#include <boost/asio/write.hpp>

namespace fptn::protocol::vk_turn {

namespace {

constexpr int kWindowSize = 512;
// Stop reading TCP while this many segments wait for an acknowledgement.
constexpr int kMaxWaitSegments = 2 * kWindowSize;
// Stop taking data out of KCP while this much waits for the TCP socket.
constexpr std::size_t kMaxWriteQueueBytes = 4 * 1024 * 1024;
constexpr auto kIdleTimeout = std::chrono::seconds(120);
constexpr auto kCloseFlushTimeout = std::chrono::seconds(10);
constexpr std::size_t kKcpHeaderSize = 24;
constexpr std::uint8_t kKcpCmdPush = 81;

std::uint32_t ReadUint32Be(const std::uint8_t* data) {
  return (static_cast<std::uint32_t>(data[0]) << 24) |
         (static_cast<std::uint32_t>(data[1]) << 16) |
         (static_cast<std::uint32_t>(data[2]) << 8) | data[3];
}

std::uint32_t ReadUint32Le(const std::uint8_t* data) {
  return (static_cast<std::uint32_t>(data[3]) << 24) |
         (static_cast<std::uint32_t>(data[2]) << 16) |
         (static_cast<std::uint32_t>(data[1]) << 8) | data[0];
}

}  // namespace

std::uint32_t KcpFrameConv(const std::uint8_t* data, std::size_t size) {
  if (size < 1 + kKcpHeaderSize || data[0] != kFrameKcp) {
    return 0;
  }
  return ReadUint32Le(data + 1);
}

bool KcpFrameOpensConversation(const std::uint8_t* data, std::size_t size) {
  if (KcpFrameConv(data, size) == 0) {
    return false;
  }
  // KCP header: conv(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4)
  std::size_t offset = 1;
  while (offset + kKcpHeaderSize <= size) {
    const std::uint8_t* segment = data + offset;
    if (segment[4] == kKcpCmdPush && ReadUint32Le(segment + 12) == 0) {
      return true;
    }
    offset += kKcpHeaderSize + ReadUint32Le(segment + 20);
  }
  return false;
}

bool KcpFrameAcknowledgesData(const std::uint8_t* data, std::size_t size) {
  return KcpFrameConv(data, size) != 0 && ReadUint32Le(data + 1 + 16) != 0;
}

std::vector<std::uint8_t> BuildCloseFrame(std::uint32_t conv) {
  return {kFrameClose, static_cast<std::uint8_t>(conv >> 24),
      static_cast<std::uint8_t>((conv >> 16) & 0xFF),
      static_cast<std::uint8_t>((conv >> 8) & 0xFF),
      static_cast<std::uint8_t>(conv & 0xFF)};
}

std::uint32_t CloseFrameConv(const std::uint8_t* data, std::size_t size) {
  if (size < 5 || data[0] != kFrameClose) {
    return 0;
  }
  return ReadUint32Be(data + 1);
}

std::uint32_t KcpClockMs() {
  return static_cast<std::uint32_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

KcpPipe::KcpPipe(
    boost::asio::ip::tcp::socket socket, std::uint32_t conv, SendDatagram send)
    : socket_(std::move(socket)),
      conv_(conv),
      send_(std::move(send)),
      kcp_(ikcp_create(conv, this)),
      last_activity_(std::chrono::steady_clock::now()) {
  ikcp_setoutput(kcp_, &KcpPipe::Output);
  // Low-latency profile: 10ms interval, fast resend, no congestion window.
  // nodelay=2 grows the retransmission timeout linearly, so the conversation
  // recovers quickly once traffic moves to a new relay.
  ikcp_nodelay(kcp_, 2, 10, 2, 1);
  // Relays come and go: the idle timeout decides when a conversation is dead
  kcp_->dead_link = std::numeric_limits<IUINT32>::max();
  ikcp_wndsize(kcp_, kWindowSize, kWindowSize);
  ikcp_setmtu(kcp_, static_cast<int>(kKcpMtu - 1));  // 1 byte for the frame
  kcp_->stream = 1;
}

KcpPipe::~KcpPipe() { ikcp_release(kcp_); }

int KcpPipe::Output(const char* buf, int len, IKCPCB* /*kcp*/, void* user) {
  auto* self = static_cast<KcpPipe*>(user);
  auto& datagram = self->datagram_;
  datagram.clear();
  datagram.push_back(kFrameKcp);
  datagram.insert(datagram.end(), reinterpret_cast<const std::uint8_t*>(buf),
      reinterpret_cast<const std::uint8_t*>(buf) + len);
  if (self->send_) {
    self->send_(datagram.data(), datagram.size());
  }
  return 0;
}

void KcpPipe::Start() {
  started_ = true;
  ReadTcp();
  WriteTcp();
}

void KcpPipe::Input(const std::uint8_t* data, std::size_t size) {
  if (finished_ || size <= 1) {
    return;
  }
  last_activity_ = std::chrono::steady_clock::now();
  ikcp_input(kcp_, reinterpret_cast<const char*>(data + 1),
      static_cast<long>(size - 1));  // NOLINT
  ikcp_flush(kcp_);                  // acknowledge right away
  DrainKcp();
}

void KcpPipe::OnPeerClosed() {
  peer_closed_ = true;
  DrainKcp();
}

void KcpPipe::Tick() {
  if (finished_) {
    return;
  }
  const auto now = std::chrono::steady_clock::now();
  ikcp_update(kcp_, KcpClockMs());
  DrainKcp();
  if (finished_) {
    return;
  }
  if (!reading_ && !tcp_eof_ && ikcp_waitsnd(kcp_) < kMaxWaitSegments) {
    ReadTcp();
  }
  if (tcp_eof_ &&
      (ikcp_waitsnd(kcp_) == 0 || now - eof_time_ > kCloseFlushTimeout)) {
    Finish();
    return;
  }
  if (now - last_activity_ > kIdleTimeout) {
    Close();
  }
}

void KcpPipe::ReadTcp() {
  if (!started_ || reading_ || tcp_eof_ || finished_ ||
      ikcp_waitsnd(kcp_) >= kMaxWaitSegments) {
    return;
  }
  reading_ = true;
  auto self = shared_from_this();
  socket_.async_read_some(boost::asio::buffer(read_buffer_),
      [this, self](boost::system::error_code ec, std::size_t size) {
        reading_ = false;
        if (finished_) {
          return;
        }
        if (ec || size == 0) {
          tcp_eof_ = true;
          eof_time_ = std::chrono::steady_clock::now();
          return;
        }
        ikcp_send(kcp_, reinterpret_cast<const char*>(read_buffer_.data()),
            static_cast<int>(size));
        ikcp_flush(kcp_);
        ReadTcp();
      });
}

// NOLINTNEXTLINE(misc-no-recursion): asynchronous chain, not a recursion
void KcpPipe::DrainKcp() {
  while (!finished_ && write_queue_bytes_ < kMaxWriteQueueBytes) {
    const int size = ikcp_peeksize(kcp_);
    if (size <= 0) {
      break;
    }
    std::vector<std::uint8_t> chunk(static_cast<std::size_t>(size));
    const int received =
        ikcp_recv(kcp_, reinterpret_cast<char*>(chunk.data()), size);
    if (received <= 0) {
      break;
    }
    chunk.resize(static_cast<std::size_t>(received));
    write_queue_bytes_ += chunk.size();
    write_queue_.push_back(std::move(chunk));
  }
  WriteTcp();
}

// NOLINTNEXTLINE(misc-no-recursion): asynchronous chain, not a recursion
void KcpPipe::WriteTcp() {
  if (!started_ || writing_ || finished_) {
    return;
  }
  if (write_queue_.empty()) {
    if (peer_closed_ && ikcp_peeksize(kcp_) <= 0) {
      Close();  // everything the peer sent has been delivered
    }
    return;
  }
  writing_ = true;
  auto self = shared_from_this();
  boost::asio::async_write(socket_, boost::asio::buffer(write_queue_.front()),
      // NOLINTNEXTLINE(misc-no-recursion)
      [this, self](boost::system::error_code ec, std::size_t /*size*/) {
        writing_ = false;
        if (finished_) {
          return;
        }
        if (ec) {
          Finish();
          return;
        }
        write_queue_bytes_ -= write_queue_.front().size();
        write_queue_.pop_front();
        DrainKcp();
      });
}

void KcpPipe::Finish() {
  if (finished_) {
    return;
  }
  // Datagrams may be lost, so the close notice goes out twice; the idle
  // timeout covers the rest.
  const auto frame = BuildCloseFrame(conv_);
  if (send_) {
    send_(frame.data(), frame.size());
    send_(frame.data(), frame.size());
  }
  Close();
}

void KcpPipe::Close() {
  if (finished_) {
    return;
  }
  finished_ = true;
  boost::system::error_code ec;
  socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
  socket_.close(ec);
}

}  // namespace fptn::protocol::vk_turn
