// osi.cpp - Educational 7-layer OSI stack in C++17 (single file, POSIX sockets only).
//
//   L7 Application   : chat / file transfer / blob+digest / ping  (App)
//   L6 Presentation  : binary serialization, UTF-8 sanitising, RLE compression,
//                      encryption + authentication tag               (Presentation)
//   L5 Session       : handshake, mutual auth (HMAC-SHA256), session id, checkpoints
//                      (SYNC), keepalive, orderly BYE                (Session)
//   L4 Transport     : TCP-like reliable stream (handshake, seq/ack, go-back-N window,
//                      retransmit timer, FIN close) + UDP-like datagrams  (Transport)
//   L3 Network       : IPv4-like addressing, header checksum, TTL, fragmentation and
//                      reassembly, ICMP echo (ping)                  (Network)
//   L2 Data link     : MAC addressing, framing, CRC-32, ARP          (DataLink)
//   L1 Physical      : the "wire" - one UDP socket carrying raw frames, with optional
//                      simulated loss / bit corruption               (Physical)
//
// Memory: all frames live in a fixed-size BufferPool (RAII `Buf` handles with headroom for
// zero-copy header push/pull, double-free detection, leak report at exit). Everything else
// uses std containers - there is no raw new/delete in this file.
//
// NOT production security: the crypto is a teaching construction. Use TLS in real software.
//
// Build: g++ -std=c++17 -O2 -Wall -Wextra osi.cpp -o osi

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

using Bytes = std::vector<uint8_t>;

// ============================================================================
// Utilities
// ============================================================================
static int g_verbose = 0;
static volatile sig_atomic_t g_stop = 0;

static uint64_t nowUs() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch()).count();
}
static uint64_t nowMs() { return nowUs() / 1000; }
static std::mt19937_64& rng() {
  static std::mt19937_64 g{std::random_device{}()};
  return g;
}

static void LOG(const char* layer, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
static void LOG(const char* layer, const char* fmt, ...) {
  if (!g_verbose) return;
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "[%-5s] ", layer);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
}
static void say(const char* tag, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
static void say(const char* tag, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  printf("[%s] ", tag);
  vprintf(fmt, ap);
  putchar('\n');
  fflush(stdout);
  va_end(ap);
}

// Big-endian writer / bounds-checked reader.
struct W {
  Bytes b;
  W& u8(uint8_t v) { b.push_back(v); return *this; }
  W& u16(uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xff); return *this; }
  W& u32(uint32_t v) { for (int i = 24; i >= 0; i -= 8) b.push_back((v >> i) & 0xff); return *this; }
  W& u64(uint64_t v) { u32(v >> 32); return u32((uint32_t)v); }
  W& raw(const uint8_t* p, size_t n) { b.insert(b.end(), p, p + n); return *this; }
  W& raw(const Bytes& v) { return raw(v.data(), v.size()); }
  W& blob(const Bytes& v) { u32((uint32_t)v.size()); return raw(v); }
  W& str(const std::string& s) { u32((uint32_t)s.size()); return raw((const uint8_t*)s.data(), s.size()); }
};
struct R {
  const uint8_t* p;
  size_t n, i = 0;
  bool ok = true;
  R(const uint8_t* p_, size_t n_) : p(p_), n(n_) {}
  explicit R(const Bytes& v) : p(v.data()), n(v.size()) {}
  bool need(size_t k) { if (!ok || n - i < k) { ok = false; return false; } return true; }
  uint8_t u8() { if (!need(1)) return 0; return p[i++]; }
  uint16_t u16() { if (!need(2)) return 0; uint16_t v = (uint16_t)((p[i] << 8) | p[i + 1]); i += 2; return v; }
  uint32_t u32() { if (!need(4)) return 0; uint32_t v = 0; for (int k = 0; k < 4; k++) v = (v << 8) | p[i + k]; i += 4; return v; }
  uint64_t u64() { uint64_t hi = u32(); uint64_t lo = u32(); return (hi << 32) | lo; }
  Bytes raw(size_t k) { if (!need(k)) return {}; Bytes v(p + i, p + i + k); i += k; return v; }
  Bytes blob() { uint32_t k = u32(); if (!ok || k > n - i) { ok = false; return {}; } return raw(k); }
  std::string str() { Bytes v = blob(); return std::string(v.begin(), v.end()); }
};

static Bytes toBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
static std::string hex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
  return s;
}

// Internet checksum (RFC 1071).
static uint32_t cksumAdd(uint32_t sum, const uint8_t* p, size_t n) {
  for (; n > 1; p += 2, n -= 2) sum += (uint32_t)((p[0] << 8) | p[1]);
  if (n) sum += (uint32_t)(p[0] << 8);
  return sum;
}
static uint16_t cksumFold(uint32_t sum) {
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (uint16_t)~sum;
}

static uint32_t crc32(const uint8_t* p, size_t n) {
  static const std::array<uint32_t, 256> T = [] {
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; i++) {
      uint32_t c = i;
      for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
      t[i] = c;
    }
    return t;
  }();
  uint32_t c = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; i++) c = T[(c ^ p[i]) & 0xff] ^ (c >> 8);
  return ~c;
}

// ---- SHA-256 / HMAC-SHA256 (used by Session auth and Presentation crypto) ----
struct Sha256 {
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  uint8_t buf[64];
  size_t bl = 0;
  uint64_t total = 0;
  static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
  void block(const uint8_t* p) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) | ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = hh + S1 + ch + K[i] + w[i];
      uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = S0 + mj;
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  void update(const uint8_t* p, size_t n) {
    total += n;
    while (n) {
      size_t k = std::min(n, 64 - bl);
      memcpy(buf + bl, p, k);
      bl += k; p += k; n -= k;
      if (bl == 64) { block(buf); bl = 0; }
    }
  }
  std::array<uint8_t, 32> final() {
    uint64_t bits = total * 8;
    uint8_t x = 0x80;
    update(&x, 1);
    x = 0;
    while (bl != 56) update(&x, 1);
    uint8_t L[8];
    for (int i = 0; i < 8; i++) L[i] = (uint8_t)(bits >> (56 - 8 * i));
    update(L, 8);
    std::array<uint8_t, 32> out;
    for (int i = 0; i < 8; i++) for (int k = 0; k < 4; k++) out[4 * i + k] = (uint8_t)(h[i] >> (24 - 8 * k));
    return out;
  }
};
static std::array<uint8_t, 32> sha256(const uint8_t* p, size_t n) { Sha256 s; s.update(p, n); return s.final(); }
static std::array<uint8_t, 32> sha256(const Bytes& v) { return sha256(v.data(), v.size()); }
static Bytes hmac(const Bytes& key, const Bytes& msg) {
  Bytes k = key;
  if (k.size() > 64) { auto d = sha256(k); k.assign(d.begin(), d.end()); }
  k.resize(64, 0);
  Bytes ip(64), op(64);
  for (int i = 0; i < 64; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
  Sha256 in; in.update(ip.data(), 64); in.update(msg.data(), msg.size());
  auto id = in.final();
  Sha256 out; out.update(op.data(), 64); out.update(id.data(), 32);
  auto od = out.final();
  return Bytes(od.begin(), od.end());
}
static bool ctEq(const Bytes& a, const Bytes& b) {  // constant-time compare
  if (a.size() != b.size()) return false;
  uint8_t d = 0;
  for (size_t i = 0; i < a.size(); i++) d |= a[i] ^ b[i];
  return d == 0;
}
static Bytes randBytes(size_t n) {
  Bytes v(n);
  for (auto& x : v) x = (uint8_t)rng()();
  return v;
}

// ============================================================================
// MEMORY MANAGEMENT: fixed pool + RAII packet buffers with headroom
// ============================================================================
class BufferPool {
 public:
  static constexpr size_t BLOCK = 2048;
  explicit BufferPool(size_t n) : n_(n), mem_(std::make_unique<uint8_t[]>(n * BLOCK)), used_(n, false) {
    for (size_t i = n; i-- > 0;) free_.push_back(i);
  }
  uint8_t* alloc() {
    if (free_.empty()) { ++failures_; return nullptr; }
    size_t i = free_.back();
    free_.pop_back();
    used_[i] = true;
    ++inUse_; ++allocs_;
    peak_ = std::max(peak_, inUse_);
    return mem_.get() + i * BLOCK;
  }
  void release(uint8_t* p) {
    if (p < mem_.get() || (size_t)(p - mem_.get()) % BLOCK != 0 || (size_t)(p - mem_.get()) / BLOCK >= n_ ||
        !used_[(size_t)(p - mem_.get()) / BLOCK]) {
      fprintf(stderr, "[mem] FATAL: invalid or double free of %p\n", (void*)p);
      abort();
    }
    used_[(size_t)(p - mem_.get()) / BLOCK] = false;
    free_.push_back((size_t)(p - mem_.get()) / BLOCK);
    --inUse_; ++frees_;
  }
  // Returns true when no blocks leaked.
  bool report() const {
    printf("[mem] pool: %zu blocks x %zu B | allocs=%llu frees=%llu peak=%zu exhausted=%llu leaked=%zu -> %s\n", n_, BLOCK,
           (unsigned long long)allocs_, (unsigned long long)frees_, peak_, (unsigned long long)failures_, inUse_,
           inUse_ == 0 ? "NO LEAKS" : "LEAK DETECTED");
    return inUse_ == 0;
  }
  size_t inUse() const { return inUse_; }

 private:
  size_t n_;
  std::unique_ptr<uint8_t[]> mem_;
  std::vector<bool> used_;
  std::vector<size_t> free_;
  size_t inUse_ = 0, peak_ = 0;
  uint64_t allocs_ = 0, frees_ = 0, failures_ = 0;
};
static BufferPool& pool() { static BufferPool p(512); return p; }

// Move-only packet buffer. Data starts after HEADROOM so each layer can push its header
// in front without copying; receivers pull headers off the front instead.
class Buf {
 public:
  static constexpr size_t HEADROOM = 64;
  Buf() = default;
  static Buf make() {
    Buf b;
    b.base_ = pool().alloc();
    if (b.base_) { b.off_ = HEADROOM; b.len_ = 0; }
    return b;
  }
  Buf(Buf&& o) noexcept { *this = std::move(o); }
  Buf& operator=(Buf&& o) noexcept {
    if (this != &o) {
      reset();
      base_ = o.base_; off_ = o.off_; len_ = o.len_;
      o.base_ = nullptr; o.off_ = o.len_ = 0;
    }
    return *this;
  }
  Buf(const Buf&) = delete;
  Buf& operator=(const Buf&) = delete;
  ~Buf() { reset(); }
  explicit operator bool() const { return base_ != nullptr; }
  uint8_t* data() { return base_ + off_; }
  const uint8_t* data() const { return base_ + off_; }
  size_t size() const { return len_; }
  uint8_t* tail() { return base_ + off_ + len_; }
  size_t tailroom() const { return BufferPool::BLOCK - off_ - len_; }
  void setLen(size_t n) { len_ = std::min(n, BufferPool::BLOCK - off_); }
  bool append(const uint8_t* p, size_t n) {
    if (!base_ || n > tailroom()) return false;
    if (n) memcpy(tail(), p, n);
    len_ += n;
    return true;
  }
  uint8_t* push(size_t n) { if (n > off_) return nullptr; off_ -= n; len_ += n; return data(); }
  bool pull(size_t n) { if (n > len_) return false; off_ += n; len_ -= n; return true; }
  void trim(size_t n) { if (n < len_) len_ = n; }

 private:
  void reset() { if (base_) { pool().release(base_); base_ = nullptr; } }
  uint8_t* base_ = nullptr;
  size_t off_ = 0, len_ = 0;
};

// ============================================================================
// LAYER 1 - PHYSICAL: the "wire" is a UDP socket that carries raw frames.
// ============================================================================
class Physical {
 public:
  std::function<void(Buf&&)> onFrame;
  int lossPct = 0, corruptPct = 0;
  uint64_t txFrames = 0, rxFrames = 0, txBytes = 0, rxBytes = 0, simDropped = 0, simCorrupted = 0, foreign = 0, noBuf = 0;

  ~Physical() { if (fd_ >= 0) ::close(fd_); }
  int fd() const { return fd_; }
  uint16_t localPort() const { return localPort_; }

  bool open(uint16_t port, const std::string& peer) {
    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) { perror("socket"); return false; }
    fcntl(fd_, F_SETFL, fcntl(fd_, F_GETFL, 0) | O_NONBLOCK);
    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (::bind(fd_, (sockaddr*)&a, sizeof a) < 0) { perror("bind"); return false; }
    socklen_t l = sizeof a;
    getsockname(fd_, (sockaddr*)&a, &l);
    localPort_ = ntohs(a.sin_port);
    if (!peer.empty()) {
      auto c = peer.rfind(':');
      if (c == std::string::npos) { fprintf(stderr, "peer must be HOST:PORT\n"); return false; }
      std::string host = peer.substr(0, c), svc = peer.substr(c + 1);
      addrinfo hints{}, *res = nullptr;
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_DGRAM;
      if (getaddrinfo(host.c_str(), svc.c_str(), &hints, &res) != 0 || !res) {
        fprintf(stderr, "cannot resolve %s\n", peer.c_str());
        return false;
      }
      peer_ = *(sockaddr_in*)res->ai_addr;
      freeaddrinfo(res);
      peerKnown_ = true;
    }
    return true;
  }

  void send(Buf&& f) {
    if (!peerKnown_) { LOG("L1", "no peer yet, frame dropped"); return; }
    if ((int)(rng()() % 100) < lossPct) { ++simDropped; LOG("L1", "SIM: frame lost on the wire"); return; }
    if (corruptPct && (int)(rng()() % 100) < corruptPct && f.size()) {
      f.data()[rng()() % f.size()] ^= (uint8_t)(1u << (rng()() % 8));
      ++simCorrupted;
      LOG("L1", "SIM: bit flipped on the wire");
    }
    ssize_t n = ::sendto(fd_, f.data(), f.size(), 0, (sockaddr*)&peer_, sizeof peer_);
    if (n > 0) { ++txFrames; txBytes += (uint64_t)n; }
  }

  void poll() {
    for (;;) {
      Buf b = Buf::make();
      sockaddr_in from{};
      socklen_t fl = sizeof from;
      ssize_t n;
      if (!b) {  // pool exhausted: read and discard so we don't spin
        uint8_t scratch[BufferPool::BLOCK];
        n = ::recvfrom(fd_, scratch, sizeof scratch, 0, (sockaddr*)&from, &fl);
        if (n < 0) return;
        ++noBuf;
        continue;
      }
      n = ::recvfrom(fd_, b.tail(), b.tailroom(), 0, (sockaddr*)&from, &fl);
      if (n < 0) return;
      if (!peerKnown_) {
        peer_ = from; peerKnown_ = true;
        char ip[64]; inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
        LOG("L1", "learned peer %s:%u", ip, ntohs(from.sin_port));
      } else if (from.sin_addr.s_addr != peer_.sin_addr.s_addr || from.sin_port != peer_.sin_port) {
        ++foreign;  // not our cable partner
        continue;
      }
      b.setLen((size_t)n);
      ++rxFrames; rxBytes += (uint64_t)n;
      if (onFrame) onFrame(std::move(b));
    }
  }
  std::string stats() const {
    std::ostringstream o;
    o << "L1 Physical : tx=" << txFrames << " frames/" << txBytes << "B rx=" << rxFrames << " frames/" << rxBytes
      << "B simLost=" << simDropped << " simCorrupt=" << simCorrupted << " foreign=" << foreign << " noBuf=" << noBuf;
    return o.str();
  }

 private:
  int fd_ = -1;
  uint16_t localPort_ = 0;
  sockaddr_in peer_{};
  bool peerKnown_ = false;
};

// ============================================================================
// LAYER 2 - DATA LINK: MAC addressing, framing, CRC-32, ARP
//   frame = dst(6) src(6) ethertype(2) len(2) payload crc32(4)
// ============================================================================
using Mac = std::array<uint8_t, 6>;
static const Mac BCAST = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
constexpr uint16_t ET_IP = 0x0800, ET_ARP = 0x0806;
static std::string macStr(const Mac& m) {
  char s[24];
  snprintf(s, sizeof s, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
  return s;
}
static std::string ipStr(uint32_t ip) {
  char s[24];
  snprintf(s, sizeof s, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
  return s;
}
static bool parseIp(const std::string& s, uint32_t& out) {
  in_addr a;
  if (inet_pton(AF_INET, s.c_str(), &a) != 1) return false;
  out = ntohl(a.s_addr);
  return true;
}

class DataLink {
 public:
  std::function<void(Buf&&)> onIp;
  uint64_t txFrames = 0, rxFrames = 0, badCrc = 0, notForUs = 0, runts = 0, arpReq = 0, arpRep = 0, arpFail = 0, noBuf = 0;
  static constexpr size_t MTU = 1500;

  DataLink(Physical& p, Mac m, uint32_t ip) : phy_(p), mac_(m), ip_(ip) {}

  void sendIp(uint32_t nextHop, Buf&& pkt) {
    auto it = arp_.find(nextHop);
    if (it != arp_.end()) { sendFrame(it->second, ET_IP, std::move(pkt)); return; }
    auto& pd = pending_[nextHop];
    if (pd.q.size() >= 8) { ++arpFail; return; }
    pd.q.push_back(std::move(pkt));
    if (pd.q.size() == 1) { pd.t = nowMs(); pd.tries = 1; arpRequest(nextHop); }
  }

  void rx(Buf&& f) {
    if (f.size() < 20) { ++runts; return; }
    const uint8_t* d = f.data();
    size_t n = f.size();
    uint32_t got = ((uint32_t)d[n - 4] << 24) | ((uint32_t)d[n - 3] << 16) | ((uint32_t)d[n - 2] << 8) | d[n - 1];
    if (crc32(d, n - 4) != got) { ++badCrc; LOG("L2", "CRC mismatch -> frame discarded"); return; }
    Mac dst, src;
    memcpy(dst.data(), d, 6);
    memcpy(src.data(), d + 6, 6);
    uint16_t type = (uint16_t)((d[12] << 8) | d[13]), len = (uint16_t)((d[14] << 8) | d[15]);
    if ((size_t)len + 20 > n) { ++runts; return; }
    if (dst != mac_ && dst != BCAST) { ++notForUs; return; }
    ++rxFrames;
    f.trim(16 + len);
    f.pull(16);
    if (type == ET_ARP) arpRx(f);
    else if (type == ET_IP && onIp) onIp(std::move(f));
  }

  void tick(uint64_t now) {
    for (auto it = pending_.begin(); it != pending_.end();) {
      if (now - it->second.t > 500) {
        if (it->second.tries >= 5) { arpFail += it->second.q.size(); it = pending_.erase(it); continue; }
        it->second.t = now; it->second.tries++;
        arpRequest(it->first);
      }
      ++it;
    }
  }
  std::string stats() const {
    std::ostringstream o;
    o << "L2 DataLink : tx=" << txFrames << " rx=" << rxFrames << " badCRC=" << badCrc << " notForUs=" << notForUs
      << " runts=" << runts << " arpReq=" << arpReq << " arpRep=" << arpRep << " arpFail=" << arpFail << " arpCache=" << arp_.size();
    return o.str();
  }

 private:
  struct Pending { std::deque<Buf> q; uint64_t t = 0; int tries = 0; };

  void sendFrame(const Mac& dst, uint16_t type, Buf&& p) {
    size_t len = p.size();
    uint8_t* h = p.push(16);
    if (!h || len > MTU) { ++noBuf; return; }
    memcpy(h, dst.data(), 6);
    memcpy(h + 6, mac_.data(), 6);
    h[12] = type >> 8; h[13] = type & 0xff; h[14] = (uint8_t)(len >> 8); h[15] = (uint8_t)len;
    uint32_t c = crc32(p.data(), p.size());
    uint8_t t[4] = {(uint8_t)(c >> 24), (uint8_t)(c >> 16), (uint8_t)(c >> 8), (uint8_t)c};
    if (!p.append(t, 4)) { ++noBuf; return; }
    ++txFrames;
    phy_.send(std::move(p));
  }
  void arpRequest(uint32_t ip) {
    Buf b = Buf::make();
    if (!b) { ++noBuf; return; }
    W w; w.u8(1).raw(mac_.data(), 6).u32(ip_).u32(ip);
    b.append(w.b.data(), w.b.size());
    ++arpReq;
    LOG("L2", "ARP who-has %s", ipStr(ip).c_str());
    sendFrame(BCAST, ET_ARP, std::move(b));
  }
  void arpRx(Buf& f) {
    R r(f.data(), f.size());
    uint8_t op = r.u8();
    Mac smac; Bytes m = r.raw(6);
    uint32_t sip = r.u32(), tip = r.u32();
    if (!r.ok) return;
    memcpy(smac.data(), m.data(), 6);
    if (sip) {
      if (arp_.find(sip) == arp_.end()) LOG("L2", "ARP learned %s is-at %s", ipStr(sip).c_str(), macStr(smac).c_str());
      arp_[sip] = smac;
      auto it = pending_.find(sip);
      if (it != pending_.end()) {
        auto q = std::move(it->second.q);
        pending_.erase(it);
        for (auto& p : q) sendFrame(smac, ET_IP, std::move(p));
      }
    }
    if (op == 1 && tip == ip_) {
      Buf b = Buf::make();
      if (!b) { ++noBuf; return; }
      W w; w.u8(2).raw(mac_.data(), 6).u32(ip_).u32(sip);
      b.append(w.b.data(), w.b.size());
      ++arpRep;
      sendFrame(smac, ET_ARP, std::move(b));
    }
  }

  Physical& phy_;
  Mac mac_;
  uint32_t ip_;
  std::map<uint32_t, Mac> arp_;
  std::map<uint32_t, Pending> pending_;
};

// ============================================================================
// LAYER 3 - NETWORK: addressing, header checksum, TTL, fragmentation, ICMP echo
//   header (20B) = ver/ihl(1)=0x45 ttl(1) proto(1) flags(1,bit0=MF) totlen(2) id(2)
//                  fragoff(2, units of 8B) cksum(2) src(4) dst(4)
// ============================================================================
constexpr uint8_t PROTO_ICMP = 1, PROTO_TCP = 6, PROTO_UDP = 17;

class Network {
 public:
  std::function<void(uint8_t, uint32_t, uint32_t, Buf&&)> onProto;
  std::function<void(uint32_t src, uint16_t seq, uint64_t rttUs)> onEchoReply;
  uint64_t tx = 0, rx = 0, badHdr = 0, badCksum = 0, notForUs = 0, ttlDrop = 0, fragsTx = 0, fragsRx = 0, reasmOk = 0,
           reasmTimeout = 0, noBuf = 0, pingRx = 0;

  Network(DataLink& dl, uint32_t ip, size_t mtu) : dl_(dl), ip_(ip), mtu_(std::min(mtu, DataLink::MTU)) {}
  uint32_t ip() const { return ip_; }

  bool send(uint8_t proto, uint32_t dst, Buf&& payload) {
    size_t plen = payload.size();
    uint16_t id = nextId_++;
    if (plen + 20 <= mtu_) return emit(proto, dst, id, 0, false, std::move(payload));
    size_t chunk = ((mtu_ - 20) / 8) * 8;
    for (size_t off = 0; off < plen; off += chunk) {
      size_t n = std::min(chunk, plen - off);
      Buf f = Buf::make();
      if (!f) { ++noBuf; return false; }
      f.append(payload.data() + off, n);
      ++fragsTx;
      if (!emit(proto, dst, id, (uint16_t)(off / 8), off + n < plen, std::move(f))) return false;
    }
    return true;
  }

  void ping(uint32_t dst, uint16_t seq) {
    Buf b = Buf::make();
    if (!b) return;
    W w; w.u8(8).u8(0).u16(0).u16(0x4F53).u16(seq).u64(nowUs());
    for (int i = 0; i < 24; i++) w.u8((uint8_t)i);
    b.append(w.b.data(), w.b.size());
    setIcmpCksum(b);
    send(PROTO_ICMP, dst, std::move(b));
  }

  void input(Buf&& pkt) {
    if (pkt.size() < 20 || pkt.data()[0] != 0x45) { ++badHdr; return; }
    const uint8_t* h = pkt.data();
    if (cksumFold(cksumAdd(0, h, 20)) != 0) { ++badCksum; LOG("L3", "bad IP header checksum"); return; }
    R r(h, 20);
    r.u8(); uint8_t ttl = r.u8(), proto = r.u8(), flags = r.u8();
    uint16_t totlen = r.u16(), id = r.u16(), fo = r.u16(); r.u16();
    uint32_t src = r.u32(), dst = r.u32();
    if (totlen < 20 || totlen > pkt.size()) { ++badHdr; return; }
    pkt.trim(totlen);
    if (dst != ip_ && dst != 0xFFFFFFFFu) { ++notForUs; return; }  // end host: no forwarding
    if (ttl == 0) { ++ttlDrop; return; }
    pkt.pull(20);
    ++rx;
    bool mf = flags & 1;
    if (!mf && fo == 0) { deliver(proto, src, dst, std::move(pkt)); return; }
    ++fragsRx;
    reassemble(proto, src, dst, id, fo, mf, pkt);
  }

  void tick(uint64_t now) {
    for (auto it = reasm_.begin(); it != reasm_.end();)
      if (now - it->second.t > 3000) { ++reasmTimeout; it = reasm_.erase(it); } else ++it;
  }
  std::string stats() const {
    std::ostringstream o;
    o << "L3 Network  : tx=" << tx << " rx=" << rx << " fragsTx=" << fragsTx << " fragsRx=" << fragsRx
      << " reassembled=" << reasmOk << " reasmTimeout=" << reasmTimeout << " badHdr=" << badHdr << " badCksum=" << badCksum
      << " notForUs=" << notForUs << " ttlDrop=" << ttlDrop << " echoReqRx=" << pingRx << " mtu=" << mtu_;
    return o.str();
  }

 private:
  struct Reasm { Bytes data; std::vector<std::pair<uint32_t, uint32_t>> got; int64_t total = -1; uint64_t t = 0; };

  bool emit(uint8_t proto, uint32_t dst, uint16_t id, uint16_t fo, bool mf, Buf&& b) {
    size_t plen = b.size();
    uint8_t* h = b.push(20);
    if (!h) { ++noBuf; return false; }
    h[0] = 0x45; h[1] = 64; h[2] = proto; h[3] = mf ? 1 : 0;
    uint16_t tot = (uint16_t)(20 + plen);
    h[4] = tot >> 8; h[5] = tot & 0xff; h[6] = id >> 8; h[7] = id & 0xff; h[8] = fo >> 8; h[9] = fo & 0xff;
    h[10] = h[11] = 0;
    h[12] = ip_ >> 24; h[13] = ip_ >> 16; h[14] = ip_ >> 8; h[15] = ip_;
    h[16] = dst >> 24; h[17] = dst >> 16; h[18] = dst >> 8; h[19] = dst;
    uint16_t c = cksumFold(cksumAdd(0, h, 20));
    h[10] = c >> 8; h[11] = c & 0xff;
    ++tx;
    dl_.sendIp(dst, std::move(b));
    return true;
  }

  void reassemble(uint8_t proto, uint32_t src, uint32_t dst, uint16_t id, uint16_t fo, bool mf, Buf& pkt) {
    auto key = std::make_tuple(src, id, proto);
    if (reasm_.find(key) == reasm_.end() && reasm_.size() >= 16) {  // bound memory: evict the oldest partial datagram
      auto oldest = reasm_.begin();
      for (auto it = reasm_.begin(); it != reasm_.end(); ++it) if (it->second.t < oldest->second.t) oldest = it;
      reasm_.erase(oldest);
      ++reasmTimeout;
    }
    auto& re = reasm_[key];
    if (re.t == 0) re.t = nowMs();
    uint32_t off = (uint32_t)fo * 8, end = off + (uint32_t)pkt.size();
    if (end > 1900) { reasm_.erase(key); return; }  // must fit one pool block
    if (re.data.size() < end) re.data.resize(end);
    memcpy(re.data.data() + off, pkt.data(), pkt.size());
    re.got.push_back({off, end});
    if (!mf) re.total = end;
    if (re.total < 0) return;
    auto g = re.got;
    std::sort(g.begin(), g.end());
    uint32_t cur = 0;
    for (auto& p : g) { if (p.first > cur) return; cur = std::max(cur, p.second); }
    if ((int64_t)cur < re.total) return;
    Buf b = Buf::make();
    if (!b) { ++noBuf; reasm_.erase(key); return; }
    b.append(re.data.data(), (size_t)re.total);
    reasm_.erase(key);
    ++reasmOk;
    LOG("L3", "reassembled datagram id=%u (%zu bytes)", id, b.size());
    deliver(proto, src, dst, std::move(b));
  }

  void setIcmpCksum(Buf& b) {
    b.data()[2] = b.data()[3] = 0;
    uint16_t c = cksumFold(cksumAdd(0, b.data(), b.size()));
    b.data()[2] = c >> 8; b.data()[3] = c & 0xff;
  }

  void deliver(uint8_t proto, uint32_t src, uint32_t dst, Buf&& b) {
    if (proto != PROTO_ICMP) { if (onProto) onProto(proto, src, dst, std::move(b)); return; }
    if (b.size() < 8 || cksumFold(cksumAdd(0, b.data(), b.size())) != 0) { ++badCksum; return; }
    R r(b.data(), b.size());
    uint8_t type = r.u8(); r.u8(); r.u16(); r.u16();
    uint16_t seq = r.u16();
    if (type == 8) {  // echo request -> reply
      ++pingRx;
      Buf out = Buf::make();
      if (!out) { ++noBuf; return; }
      out.append(b.data(), b.size());
      out.data()[0] = 0;
      setIcmpCksum(out);
      send(PROTO_ICMP, src, std::move(out));
    } else if (type == 0 && b.size() >= 16) {
      R t(b.data() + 8, 8);
      uint64_t sent = t.u64();
      if (onEchoReply) onEchoReply(src, seq, nowUs() - sent);
    }
  }

  DataLink& dl_;
  uint32_t ip_;
  size_t mtu_;
  uint16_t nextId_ = 1;
  std::map<std::tuple<uint32_t, uint16_t, uint8_t>, Reasm> reasm_;
};

// ============================================================================
// LAYER 4 - TRANSPORT: reliable stream (TCP-like) + datagrams (UDP-like)
//   TCP-like header (18B): sport(2) dport(2) seq(4) ack(4) flags(1) rsv(1) len(2) cksum(2)
//   Mechanisms: 3-way handshake, byte sequence numbers, cumulative ACKs, go-back-N sliding
//   window, retransmission timer with backoff, in-order delivery, FIN/ACK close, TIME_WAIT, RST.
//   (No congestion control; fixed window.)
// ============================================================================
constexpr uint8_t F_FIN = 1, F_SYN = 2, F_RST = 4, F_ACK = 16;
constexpr size_t MSS = 1000, WND = 8;
constexpr uint32_t TCP_HDR = 18;
enum class TS { CLOSED, SYN_SENT, SYN_RCVD, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, LAST_ACK, TIME_WAIT };
static const char* tsName(TS s) {
  static const char* n[] = {"CLOSED", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT"};
  return n[(int)s];
}
static inline bool seqLt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }

struct TcpHdr { uint16_t sport = 0, dport = 0; uint32_t seq = 0, ack = 0; uint8_t flags = 0; uint16_t len = 0; };
struct Seg {
  uint32_t seq;
  uint8_t flags;
  Bytes data;
  uint64_t sentAt = 0;
  int tries = 0;
  uint32_t span() const { return (uint32_t)data.size() + ((flags & F_SYN) ? 1 : 0) + ((flags & F_FIN) ? 1 : 0); }
};

class Transport;
struct Conn {
  Transport* tp = nullptr;
  uint16_t lport = 0, rport = 0;
  uint32_t rip = 0;
  TS st = TS::CLOSED;
  uint32_t iss = 0, snd_una = 0, snd_nxt = 0, rcv_nxt = 0;
  std::deque<uint8_t> sendBuf;
  std::deque<Seg> inflight;
  bool closeReq = false, finSent = false, finAcked = false, peerFin = false;
  uint64_t twAt = 0;
  std::function<void(Bytes&&)> onData;
  std::function<void(TS)> onState;

  void send(const Bytes& d);
  void close();
  void abort();
  void pump();
  void tick(uint64_t now);
  void onSegment(const TcpHdr& h, Bytes&& data);
  void transmit(Seg& s);
  void sendAck();
  void handleAck(uint32_t ack, bool pure);
  int dup = 0;
  void setState(TS s);
};
using ConnPtr = std::shared_ptr<Conn>;

class Transport {
 public:
  uint64_t segTx = 0, segRx = 0, retx = 0, badCksum = 0, badSeg = 0, rstTx = 0, udpTx = 0, udpRx = 0, noBuf = 0, dupAcks = 0;

  explicit Transport(Network& n) : net_(n) {}

  void listen(uint16_t port, std::function<void(ConnPtr)> cb) { listeners_[port] = std::move(cb); }
  void bindUdp(uint16_t port, std::function<void(uint32_t, uint16_t, Bytes&&)> cb) { udp_[port] = std::move(cb); }

  ConnPtr connect(uint32_t ip, uint16_t port) {
    auto c = std::make_shared<Conn>();
    c->tp = this;
    c->lport = nextPort_++;
    if (nextPort_ == 0) nextPort_ = 49152;
    c->rip = ip; c->rport = port;
    c->iss = (uint32_t)rng()();
    c->snd_una = c->iss; c->snd_nxt = c->iss + 1;
    c->st = TS::SYN_SENT;
    c->inflight.push_back(Seg{c->iss, F_SYN, {}});
    conns_[std::make_tuple(c->lport, ip, port)] = c;
    c->transmit(c->inflight.back());
    return c;
  }

  void sendUdp(uint32_t dip, uint16_t sport, uint16_t dport, const Bytes& d) {
    if (d.size() > MSS) return;
    Buf b = Buf::make();
    if (!b) { ++noBuf; return; }
    b.append(d.data(), d.size());
    uint8_t* h = b.push(8);
    uint16_t len = (uint16_t)b.size();
    h[0] = sport >> 8; h[1] = sport & 0xff; h[2] = dport >> 8; h[3] = dport & 0xff;
    h[4] = len >> 8; h[5] = len & 0xff; h[6] = h[7] = 0;
    uint16_t c = cksumFold(cksumAdd(pseudo(net_.ip(), dip, PROTO_UDP, b.size()), b.data(), b.size()));
    if (c == 0) c = 0xffff;
    h[6] = c >> 8; h[7] = c & 0xff;
    ++udpTx;
    net_.send(PROTO_UDP, dip, std::move(b));
  }

  void input(uint8_t proto, uint32_t src, uint32_t dst, Buf&& b) {
    if (proto == PROTO_TCP) rxTcp(src, dst, b);
    else if (proto == PROTO_UDP) rxUdp(src, dst, b);
  }

  void emit(uint32_t dst, uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags, const uint8_t* d, size_t n) {
    Buf b = Buf::make();
    if (!b) { ++noBuf; return; }
    b.append(d, n);
    uint8_t* h = b.push(TCP_HDR);
    h[0] = sport >> 8; h[1] = sport & 0xff; h[2] = dport >> 8; h[3] = dport & 0xff;
    for (int i = 0; i < 4; i++) { h[4 + i] = (uint8_t)(seq >> (24 - 8 * i)); h[8 + i] = (uint8_t)(ack >> (24 - 8 * i)); }
    h[12] = flags; h[13] = 0; h[14] = (uint8_t)(n >> 8); h[15] = (uint8_t)n; h[16] = h[17] = 0;
    uint16_t c = cksumFold(cksumAdd(pseudo(net_.ip(), dst, PROTO_TCP, b.size()), b.data(), b.size()));
    h[16] = c >> 8; h[17] = c & 0xff;
    net_.send(PROTO_TCP, dst, std::move(b));
  }

  void tick(uint64_t now) {
    std::vector<ConnPtr> v;
    for (auto& kv : conns_) v.push_back(kv.second);
    for (auto& c : v) c->tick(now);
    for (auto it = conns_.begin(); it != conns_.end();)
      it = (it->second->st == TS::CLOSED) ? conns_.erase(it) : std::next(it);
  }
  std::string stats() const {
    std::ostringstream o;
    o << "L4 Transport: segTx=" << segTx << " segRx=" << segRx << " retransmits=" << retx << " badCksum=" << badCksum
      << " badSeg=" << badSeg << " rstTx=" << rstTx << " udpTx=" << udpTx << " udpRx=" << udpRx << " conns=" << conns_.size();
    return o.str();
  }

 private:
  static uint32_t pseudo(uint32_t s, uint32_t d, uint8_t proto, size_t len) {
    return (s >> 16) + (s & 0xffff) + (d >> 16) + (d & 0xffff) + proto + (uint32_t)len;
  }

  void rxUdp(uint32_t src, uint32_t dst, Buf& b) {
    if (b.size() < 8 || cksumFold(cksumAdd(pseudo(src, dst, PROTO_UDP, b.size()), b.data(), b.size())) != 0) { ++badCksum; return; }
    R r(b.data(), b.size());
    uint16_t sport = r.u16(), dport = r.u16(), len = r.u16();
    if (len < 8 || len > b.size()) { ++badSeg; return; }
    auto it = udp_.find(dport);
    if (it == udp_.end()) return;
    ++udpRx;
    it->second(src, sport, Bytes(b.data() + 8, b.data() + len));
  }

  void rxTcp(uint32_t src, uint32_t dst, Buf& b) {
    if (b.size() < TCP_HDR) { ++badSeg; return; }
    if (cksumFold(cksumAdd(pseudo(src, dst, PROTO_TCP, b.size()), b.data(), b.size())) != 0) {
      ++badCksum; LOG("L4", "bad segment checksum -> dropped"); return;
    }
    R r(b.data(), b.size());
    TcpHdr h;
    h.sport = r.u16(); h.dport = r.u16(); h.seq = r.u32(); h.ack = r.u32(); h.flags = r.u8(); r.u8(); h.len = r.u16(); r.u16();
    if (TCP_HDR + h.len > b.size()) { ++badSeg; return; }
    ++segRx;
    Bytes data(b.data() + TCP_HDR, b.data() + TCP_HDR + h.len);
    auto it = conns_.find(std::make_tuple(h.dport, src, h.sport));
    if (it != conns_.end()) { ConnPtr c = it->second; c->onSegment(h, std::move(data)); return; }
    if (h.flags & F_RST) return;
    if ((h.flags & F_SYN) && !(h.flags & F_ACK)) {
      auto l = listeners_.find(h.dport);
      if (l != listeners_.end()) {
        auto c = std::make_shared<Conn>();
        c->tp = this; c->lport = h.dport; c->rip = src; c->rport = h.sport;
        c->iss = (uint32_t)rng()();
        c->snd_una = c->iss; c->snd_nxt = c->iss + 1;
        c->rcv_nxt = h.seq + 1;
        c->st = TS::SYN_RCVD;
        c->inflight.push_back(Seg{c->iss, (uint8_t)(F_SYN | F_ACK), {}});
        conns_[std::make_tuple(c->lport, src, c->rport)] = c;
        l->second(c);  // application may adopt or abort()
        if (c->st == TS::SYN_RCVD) c->transmit(c->inflight.back());
        return;
      }
    }
    ++rstTx;
    emit(src, h.dport, h.sport, h.ack, h.seq + h.len + ((h.flags & (F_SYN | F_FIN)) ? 1 : 0), F_RST | F_ACK, nullptr, 0);
  }

  Network& net_;
  std::map<std::tuple<uint16_t, uint32_t, uint16_t>, ConnPtr> conns_;
  std::map<uint16_t, std::function<void(ConnPtr)>> listeners_;
  std::map<uint16_t, std::function<void(uint32_t, uint16_t, Bytes&&)>> udp_;
  uint16_t nextPort_ = 49152;
};

// ---- Conn implementation ----
void Conn::setState(TS s) {
  if (st == s) return;
  LOG("L4", "conn %u->%s:%u  %s -> %s", lport, ipStr(rip).c_str(), rport, tsName(st), tsName(s));
  st = s;
  if (s == TS::TIME_WAIT) twAt = nowMs();
  if (onState) onState(s);
}
void Conn::transmit(Seg& s) {
  s.sentAt = nowMs();
  ++tp->segTx;
  if (s.tries > 0) ++tp->retx;
  tp->emit(rip, lport, rport, s.seq, rcv_nxt, s.flags, s.data.data(), s.data.size());
}
void Conn::sendAck() { tp->emit(rip, lport, rport, snd_nxt, rcv_nxt, F_ACK, nullptr, 0); }
void Conn::send(const Bytes& d) {
  if (st == TS::CLOSED || closeReq) return;
  sendBuf.insert(sendBuf.end(), d.begin(), d.end());
  pump();
}
void Conn::close() {
  switch (st) {
    case TS::SYN_SENT: case TS::SYN_RCVD: abort(); return;
    case TS::CLOSED: case TS::TIME_WAIT: return;
    default: closeReq = true; pump();
  }
}
void Conn::abort() {
  if (st == TS::CLOSED) return;
  tp->emit(rip, lport, rport, snd_nxt, rcv_nxt, F_RST | F_ACK, nullptr, 0);
  ++tp->rstTx;
  inflight.clear(); sendBuf.clear();
  setState(TS::CLOSED);
}
void Conn::pump() {
  if (st != TS::ESTABLISHED && st != TS::CLOSE_WAIT) return;
  while (inflight.size() < WND && !sendBuf.empty()) {
    size_t n = std::min(MSS, sendBuf.size());
    Seg s{snd_nxt, F_ACK, Bytes(sendBuf.begin(), sendBuf.begin() + (long)n)};
    sendBuf.erase(sendBuf.begin(), sendBuf.begin() + (long)n);
    snd_nxt += (uint32_t)n;
    inflight.push_back(std::move(s));
    transmit(inflight.back());
  }
  if (closeReq && sendBuf.empty() && !finSent && inflight.size() < WND) {
    inflight.push_back(Seg{snd_nxt, (uint8_t)(F_FIN | F_ACK), {}});
    snd_nxt += 1;
    finSent = true;
    transmit(inflight.back());
    setState(st == TS::ESTABLISHED ? TS::FIN_WAIT : TS::LAST_ACK);
  }
}
void Conn::handleAck(uint32_t ack, bool pure) {
  if (!seqLt(snd_una, ack) || seqLt(snd_nxt, ack)) {
    if (pure && ack == snd_una && !inflight.empty()) {
      ++tp->dupAcks;
      if (++dup == 3) {  // fast retransmit: the receiver keeps asking for the same byte
        dup = 0;
        for (auto& s : inflight) { s.tries++; transmit(s); }
      }
    }
    return;
  }
  dup = 0;
  while (!inflight.empty() && !seqLt(ack, inflight.front().seq + inflight.front().span())) {
    if (inflight.front().flags & F_FIN) finAcked = true;
    inflight.pop_front();
  }
  snd_una = ack;
  for (auto& s : inflight) s.tries = 0;  // progress: reset backoff
}
void Conn::onSegment(const TcpHdr& h, Bytes&& data) {
  if (h.flags & F_RST) { inflight.clear(); sendBuf.clear(); setState(TS::CLOSED); return; }
  if (st == TS::CLOSED) return;
  if (st == TS::SYN_SENT) {
    if ((h.flags & (F_SYN | F_ACK)) == (F_SYN | F_ACK) && h.ack == snd_nxt) {
      rcv_nxt = h.seq + 1;
      handleAck(h.ack, false);
      setState(TS::ESTABLISHED);
      sendAck();
      pump();
    }
    return;
  }
  if (h.flags & F_SYN) {  // duplicate handshake segment
    if (st == TS::SYN_RCVD && !inflight.empty()) { inflight.front().tries++; transmit(inflight.front()); }
    else if (h.flags & F_ACK) sendAck();
    return;
  }
  if (h.flags & F_ACK) handleAck(h.ack, data.empty() && !(h.flags & F_FIN));
  if (st == TS::SYN_RCVD && snd_una == snd_nxt) setState(TS::ESTABLISHED);
  bool fin = h.flags & F_FIN;
  if (!data.empty() || fin) {
    if (h.seq == rcv_nxt) {  // in-order only (go-back-N receiver)
      if (!data.empty()) { rcv_nxt += (uint32_t)data.size(); if (onData) onData(std::move(data)); }
      if (fin && !peerFin) { peerFin = true; rcv_nxt += 1; }
    }
    sendAck();  // also acts as a duplicate ACK for out-of-order arrivals
  }
  if (peerFin && st == TS::ESTABLISHED) setState(TS::CLOSE_WAIT);
  if (st == TS::FIN_WAIT && finAcked && peerFin) setState(TS::TIME_WAIT);
  if (st == TS::LAST_ACK && finAcked) setState(TS::CLOSED);
  pump();
}
void Conn::tick(uint64_t now) {
  pump();
  if (st == TS::TIME_WAIT && now - twAt > 1500) { setState(TS::CLOSED); return; }
  if (inflight.empty() || st == TS::CLOSED) return;
  Seg& f = inflight.front();
  uint64_t rto = std::min<uint64_t>(2000, 300ull << std::min(f.tries, 3));
  if (now - f.sentAt < rto) return;
  if (f.tries >= 10) { LOG("L4", "too many retransmissions -> reset"); abort(); return; }
  for (auto& s : inflight) { s.tries++; transmit(s); }  // go-back-N
}

// ============================================================================
// LAYER 5 - SESSION: dialogue control on top of the byte stream
//   frame = type(1) sid(4) seq(4) len(4) payload
//   HELLO(cnonce) -> WELCOME(sid,snonce) -> AUTH(HMAC) -> ACCEPT(HMAC) = mutual authentication
//   DATA(seq) with SYNC checkpoints every 8 messages, PING/PONG keepalive, BYE.
// ============================================================================
class Session {
 public:
  std::function<void()> onUp, onDown;
  std::function<void(Bytes&&)> onData;
  uint32_t checkpoints = 0, sent = 0, received = 0;

  Session(ConnPtr c, bool client, std::string secret) : c_(std::move(c)), client_(client), secret_(toBytes(secret)) {
    created_ = lastRx_ = lastTx_ = nowMs();
    c_->onData = [this](Bytes&& d) { rx(std::move(d)); };
    c_->onState = [this](TS s) { stateChanged(s); };
  }
  ~Session() {
    if (c_) { c_->onData = nullptr; c_->onState = nullptr; if (c_->st != TS::CLOSED) c_->close(); }
  }
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  bool up() const { return st_ == UP; }
  uint32_t id() const { return sid_; }
  const Bytes& key() const { return key_; }

  void sendData(const Bytes& d) {
    if (st_ == UP) { ++sent; sendFrame(DATA, ++txSeq_, d); }
    else if (st_ != DOWN) pendingTx_.push_back(d);
  }
  void close() {
    if (st_ == UP) sendFrame(BYE, 0, {});
    st_ = DOWN;
    c_->close();
  }
  void tick(uint64_t now) {
    if (st_ == UP) {
      if (now - lastTx_ > 3000) sendFrame(PING, 0, {});
      if (now - lastRx_ > 15000) fail("keepalive timeout");
    } else if (st_ != DOWN && now - created_ > 10000) fail("handshake timeout");
  }
  std::string stats() const {
    std::ostringstream o;
    o << "L5 Session  : sid=" << sid_ << " sent=" << sent << " received=" << received << " checkpointsSeen=" << checkpoints;
    return o.str();
  }

 private:
  enum Type : uint8_t { HELLO = 1, WELCOME, AUTH, ACCEPT, DENY, DATA, SYNC, PING, PONG, BYE };
  enum St { INIT, WAIT_WELCOME, WAIT_AUTH, WAIT_ACCEPT, UP, DOWN };
  static constexpr uint32_t MAXF = 16u << 20;

  void sendFrame(Type t, uint32_t seq, const Bytes& p) {
    W w; w.u8(t).u32(sid_).u32(seq).u32((uint32_t)p.size()).raw(p);
    lastTx_ = nowMs();
    c_->send(w.b);
  }
  void fail(const char* why) {
    LOG("L5", "session failure: %s", why);
    st_ = DOWN;
    c_->abort();
  }
  void notifyDown() { if (!downFired_) { downFired_ = true; if (onDown) onDown(); } }
  void stateChanged(TS s) {
    if (s == TS::ESTABLISHED && client_ && st_ == INIT) {
      cn_ = randBytes(16);
      sendFrame(HELLO, 0, cn_);
      st_ = WAIT_WELCOME;
    } else if (s == TS::CLOSE_WAIT) c_->close();
    else if (s == TS::CLOSED) { st_ = DOWN; notifyDown(); }
  }
  Bytes proof(char role) const { W w; w.u8((uint8_t)role).raw(cn_).raw(sn_); return hmac(secret_, w.b); }
  void becomeUp() {
    W w; w.u8('K').raw(cn_).raw(sn_);
    key_ = hmac(secret_, w.b);
    st_ = UP;
    LOG("L5", "session %u established (%s)", sid_, client_ ? "client" : "server");
    for (auto& d : pendingTx_) { ++sent; sendFrame(DATA, ++txSeq_, d); }
    pendingTx_.clear();
    if (onUp) onUp();
  }
  void rx(Bytes&& d) {
    lastRx_ = nowMs();  // any bytes from the peer prove it is alive, even mid-transfer
    rx_.insert(rx_.end(), d.begin(), d.end());
    while (rx_.size() >= 13 && st_ != DOWN) {
      R r(rx_);
      uint8_t type = r.u8(); uint32_t sid = r.u32(), seq = r.u32(), len = r.u32();
      if (len > MAXF) { fail("oversized frame"); return; }
      if (rx_.size() < 13 + (size_t)len) break;
      Bytes payload(rx_.begin() + 13, rx_.begin() + 13 + len);
      rx_.erase(rx_.begin(), rx_.begin() + 13 + len);
      lastRx_ = nowMs();
      handle((Type)type, sid, seq, std::move(payload));
    }
  }
  void handle(Type type, uint32_t sid, uint32_t seq, Bytes&& p) {
    switch (type) {
      case HELLO:
        if (client_ || st_ != INIT || p.size() != 16) { fail("bad HELLO"); return; }
        cn_ = p; sn_ = randBytes(16);
        sid_ = (uint32_t)(rng()() | 1);
        sendFrame(WELCOME, 0, sn_);
        st_ = WAIT_AUTH;
        break;
      case WELCOME:
        if (!client_ || st_ != WAIT_WELCOME || p.size() != 16) { fail("bad WELCOME"); return; }
        sn_ = p; sid_ = sid;
        sendFrame(AUTH, 0, proof('C'));
        st_ = WAIT_ACCEPT;
        break;
      case AUTH:
        if (client_ || st_ != WAIT_AUTH || sid != sid_) { fail("bad AUTH"); return; }
        if (!ctEq(p, proof('C'))) { sendFrame(DENY, 0, {}); st_ = DOWN; c_->close(); LOG("L5", "authentication failed"); return; }
        sendFrame(ACCEPT, 0, proof('S'));
        becomeUp();
        break;
      case ACCEPT:
        if (!client_ || st_ != WAIT_ACCEPT || !ctEq(p, proof('S'))) { fail("server authentication failed"); return; }
        becomeUp();
        break;
      case DENY: st_ = DOWN; c_->close(); say("session", "authentication denied by peer (wrong --key?)"); break;
      case DATA:
        if (st_ != UP || sid != sid_ || seq != rxSeq_ + 1) { fail("bad DATA"); return; }
        ++rxSeq_; ++received;
        if (onData) onData(std::move(p));
        if (rxSeq_ % 8 == 0) sendFrame(SYNC, rxSeq_, {});
        break;
      case SYNC: ++checkpoints; synced_ = seq; break;
      case PING: if (st_ == UP) sendFrame(PONG, 0, {}); break;
      case PONG: break;
      case BYE: st_ = DOWN; c_->close(); break;
      default: fail("unknown frame type");
    }
  }

  ConnPtr c_;
  bool client_;
  Bytes secret_, cn_, sn_, key_, rx_;
  std::deque<Bytes> pendingTx_;
  St st_ = INIT;
  uint32_t sid_ = 0, txSeq_ = 0, rxSeq_ = 0, synced_ = 0;
  uint64_t created_ = 0, lastRx_ = 0, lastTx_ = 0;
  bool downFired_ = false;
};

// ============================================================================
// LAYER 6 - PRESENTATION: representation, compression, encryption
//   AppMsg --serialize--> bytes --RLE (if smaller)--> --encrypt+tag--> wire
//   wire = flags(1) nonce(8) body [tag(16)]; flags bit0=compressed bit1=encrypted
//   keystream = SHA256(key|'E'|nonce|block); tag = HMAC(key, 'T'|flags|nonce|body)[:16];
//   nonce low bit = sender role so both directions never reuse a keystream.
// ============================================================================
enum MsgType : uint8_t { M_CHAT = 1, M_FILE, M_PING, M_PONG, M_BLOB, M_BLOBACK };
struct AppMsg {
  uint8_t type = 0;
  uint64_t id = 0, ts = 0;
  std::string name;
  Bytes body;
};

static Bytes rleEnc(const Bytes& in) {  // PackBits-style: c<128 literal c+1 bytes; c>=129 run of c-126
  Bytes out;
  size_t i = 0, n = in.size();
  while (i < n) {
    size_t run = 1;
    while (i + run < n && in[i + run] == in[i] && run < 129) ++run;
    if (run >= 3) { out.push_back((uint8_t)(126 + run)); out.push_back(in[i]); i += run; continue; }
    size_t s = i, lit = 0;
    while (i < n && lit < 128) {
      size_t r = 1;
      while (i + r < n && in[i + r] == in[i] && r < 3) ++r;
      if (r >= 3) break;
      ++i; ++lit;
    }
    out.push_back((uint8_t)(lit - 1));
    out.insert(out.end(), in.begin() + (long)s, in.begin() + (long)(s + lit));
  }
  return out;
}
static bool rleDec(const Bytes& in, Bytes& out, size_t cap) {
  size_t i = 0;
  while (i < in.size()) {
    uint8_t c = in[i++];
    if (c < 128) {
      size_t k = (size_t)c + 1;
      if (i + k > in.size() || out.size() + k > cap) return false;
      out.insert(out.end(), in.begin() + (long)i, in.begin() + (long)(i + k));
      i += k;
    } else if (c >= 129) {
      size_t k = (size_t)c - 126;
      if (i >= in.size() || out.size() + k > cap) return false;
      out.insert(out.end(), k, in[i++]);
    } else return false;
  }
  return true;
}
static void xorStream(const Bytes& key, uint64_t nonce, Bytes& d) {
  uint64_t blk = 0;
  for (size_t off = 0; off < d.size(); off += 32, ++blk) {
    W w; w.raw(key).u8('E').u64(nonce).u64(blk);
    auto ks = sha256(w.b);
    for (size_t j = 0; j < 32 && off + j < d.size(); j++) d[off + j] ^= ks[j];
  }
}
// Replace invalid UTF-8 and control characters (blocks terminal-escape injection).
static std::string sanitizeUtf8(const std::string& s) {
  std::string o;
  size_t i = 0;
  while (i < s.size()) {
    uint8_t c = (uint8_t)s[i];
    size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    bool ok = n && i + n <= s.size();
    for (size_t k = 1; ok && k < n; k++) ok = ((uint8_t)s[i + k] & 0xC0) == 0x80;
    if (!ok || (n == 1 && ((c < 0x20 && c != '\t') || c == 0x7f))) { o += '?'; ++i; }
    else { o.append(s, i, n); i += n; }
  }
  return o;
}

class Presentation {
 public:
  uint64_t plainOut = 0, wireOut = 0, plainIn = 0, wireIn = 0, compressed = 0, rejected = 0;
  Presentation(bool client, bool comp, bool enc) : roleBit_(client ? 0 : 1), comp_(comp), enc_(enc) {}
  void setKey(Bytes k) { key_ = std::move(k); }

  Bytes encode(const AppMsg& m) {
    W s; s.u8(m.type).u64(m.id).u64(m.ts).str(m.name).blob(m.body);
    Bytes body = s.b;
    plainOut += body.size();
    uint8_t flags = 0;
    if (comp_) {
      Bytes c = rleEnc(body);
      if (c.size() < body.size()) { body = std::move(c); flags |= 1; ++compressed; }
    }
    uint64_t nonce = 0;
    if (enc_ && !key_.empty()) {
      nonce = (ctr_++ << 1) | (uint64_t)roleBit_;
      xorStream(key_, nonce, body);
      flags |= 2;
    }
    W w; w.u8(flags).u64(nonce).raw(body);
    if (flags & 2) {
      W t; t.u8('T').u8(flags).u64(nonce).raw(body);
      Bytes tag = hmac(key_, t.b);
      w.raw(tag.data(), 16);
    }
    wireOut += w.b.size();
    return w.b;
  }

  bool decode(const Bytes& wire, AppMsg& m) {
    wireIn += wire.size();
    R r(wire);
    uint8_t flags = r.u8();
    uint64_t nonce = r.u64();
    if (!r.ok) { ++rejected; return false; }
    if (enc_ && !(flags & 2)) { ++rejected; return false; }  // downgrade protection
    Bytes body(wire.begin() + 9, wire.end());
    if (flags & 2) {
      if (key_.empty() || body.size() < 16) { ++rejected; return false; }
      Bytes tag(body.end() - 16, body.end());
      body.resize(body.size() - 16);
      W t; t.u8('T').u8(flags).u64(nonce).raw(body);
      Bytes want = hmac(key_, t.b);
      want.resize(16);
      if (!ctEq(tag, want) || (int)(nonce & 1) == roleBit_) { ++rejected; LOG("L6", "authentication tag mismatch"); return false; }
      xorStream(key_, nonce, body);
    }
    if (flags & 1) {
      Bytes out;
      if (!rleDec(body, out, 32u << 20)) { ++rejected; return false; }
      body = std::move(out);
    }
    plainIn += body.size();
    R p(body);
    m.type = p.u8(); m.id = p.u64(); m.ts = p.u64(); m.name = p.str(); m.body = p.blob();
    if (!p.ok) { ++rejected; return false; }
    return true;
  }
  std::string stats() const {
    std::ostringstream o;
    o << "L6 Present. : plainOut=" << plainOut << "B wireOut=" << wireOut << "B (compressedMsgs=" << compressed
      << ") plainIn=" << plainIn << "B wireIn=" << wireIn << "B rejected=" << rejected;
    return o.str();
  }

 private:
  Bytes key_;
  uint64_t ctr_ = 0;
  int roleBit_;
  bool comp_, enc_;
};

// ============================================================================
// LAYER 7 - APPLICATION: chat, file transfer, blob + SHA-256 verification, ping
// ============================================================================
struct Config {
  bool client = false, test = false, once = false, compress = true, encrypt = true;
  uint16_t listenPort = 0, appPort = 7000;
  std::string peer, secret = "osi-demo-secret";
  uint32_t ip = 0, peerIp = 0;
  int loss = 0, corrupt = 0;
  size_t mtu = 1500;
};
constexpr uint16_t UDP_PORT = 7001;

class App {
 public:
  std::function<std::string()> lowerStats;
  App(Transport& tp, Network& net, const Config& c) : tp_(tp), net_(net), cfg_(c) {}

  bool finished() const { return finished_; }
  int exitCode() const { return (testFail_ || testTimeout_ || (cfg_.test && cfg_.client && !testDone_)) ? 1 : 0; }

  void start() {
    tp_.bindUdp(UDP_PORT, [this](uint32_t ip, uint16_t port, Bytes&& d) { onUdp(ip, port, std::move(d)); });
    net_.onEchoReply = [this](uint32_t src, uint16_t seq, uint64_t us) {
      say("icmp", "reply from %s: seq=%u time=%.3f ms", ipStr(src).c_str(), seq, us / 1000.0);
      if (seq >= 1 && seq <= 3 && !(pingMask_ & (1u << seq))) { pingMask_ |= 1u << seq; ++pingsOk_; }
    };
    if (cfg_.client) {
      say("app", "connecting to %s:%u ...", ipStr(cfg_.peerIp).c_str(), cfg_.appPort);
      attach(tp_.connect(cfg_.peerIp, cfg_.appPort), true);
    } else {
      tp_.listen(cfg_.appPort, [this](ConnPtr c) {
        if (ses_) { c->abort(); return; }  // one session at a time
        attach(c, false);
      });
      say("app", "server %s listening on virtual port %u (UDP wire port from --listen)", ipStr(cfg_.ip).c_str(), cfg_.appPort);
    }
    help();
  }

  void tick(uint64_t now) {
    if (ses_) ses_->tick(now);
    if (dead_) {
      say("app", "session closed");
      ses_.reset(); pres_.reset();
      dead_ = false; up_ = false;
      if (cfg_.client || cfg_.once) finished_ = true;
      else say("app", "waiting for a new connection");
    }
    if (quitting_ && now > quitDeadline_) finished_ = true;
    if (cfg_.test && cfg_.client) checkTests(now);
  }

  void command(const std::string& line) {
    if (line.empty()) return;
    if (line[0] != '/') { chat(line); return; }
    std::istringstream is(line);
    std::string c, rest;
    is >> c;
    std::getline(is, rest);
    if (!rest.empty() && rest[0] == ' ') rest.erase(0, 1);
    if (c == "/quit") {
      if (ses_) ses_->close();
      quitting_ = true; quitDeadline_ = nowMs() + 5000;
      if (!ses_) finished_ = true;
    } else if (c == "/ping") net_.ping(cfg_.peerIp, (uint16_t)++pingSeq_);
    else if (c == "/stats") printStats();
    else if (c == "/udp") tp_.sendUdp(cfg_.peerIp, UDP_PORT, UDP_PORT, toBytes(rest));
    else if (c == "/send") chat(rest);
    else if (c == "/file") sendFile(rest);
    else if (c == "/blob") {
      size_t kb = (size_t)std::max(1, atoi(rest.c_str()));
      Bytes b(kb * 1024);
      for (auto& x : b) x = (uint8_t)rng()();
      AppMsg m{M_BLOB, ++nextId_, nowMs(), cfg_.client ? "client" : "server", b};
      auto d = sha256(b);
      expect_[m.id] = {hex(d.data(), 32), "blob"};
      sendMsg(m);
    } else help();
  }

  void printStats() {
    if (lowerStats) printf("%s\n", lowerStats().c_str());
    if (ses_) printf("%s\n", ses_->stats().c_str());
    if (pres_) printf("%s\n", pres_->stats().c_str());
    fflush(stdout);
  }

 private:
  struct Expect { std::string want; const char* what; };

  void help() {
    say("app", "commands: <text> | /ping | /udp TEXT | /file PATH | /blob KB | /stats | /quit");
  }

  void attach(ConnPtr c, bool client) {
    pres_ = std::make_unique<Presentation>(client, cfg_.compress, cfg_.encrypt);
    ses_ = std::make_unique<Session>(c, client, cfg_.secret);
    ses_->onUp = [this] {
      pres_->setKey(ses_->key());
      up_ = true;
      say("app", "session %u established - authenticated, encrypted=%s compress=%s", ses_->id(), cfg_.encrypt ? "yes" : "no",
          cfg_.compress ? "yes" : "no");
      if (cfg_.test && cfg_.client) runTests();
    };
    ses_->onData = [this](Bytes&& d) {
      AppMsg m;
      if (!pres_->decode(d, m)) { say("app", "dropped a message that failed presentation checks"); return; }
      handle(m);
    };
    ses_->onDown = [this] { dead_ = true; up_ = false; };
  }

  std::string me() const { return cfg_.client ? "client" : "server"; }

  void sendMsg(const AppMsg& m) {
    if (!ses_ || !up_) { say("app", "not connected yet"); return; }
    ses_->sendData(pres_->encode(m));
  }
  void chat(const std::string& t) { sendMsg(AppMsg{M_CHAT, ++nextId_, nowMs(), me(), toBytes(t)}); }

  void sendFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { say("app", "cannot open %s", path.c_str()); return; }
    Bytes b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (b.size() > (8u << 20)) { say("app", "file too large (8 MiB max)"); return; }
    auto slash = path.find_last_of('/');
    AppMsg m{M_FILE, ++nextId_, nowMs(), slash == std::string::npos ? path : path.substr(slash + 1), b};
    auto d = sha256(b);
    expect_[m.id] = {hex(d.data(), 32), "file"};
    say("app", "sending %s (%zu bytes)", m.name.c_str(), b.size());
    sendMsg(m);
  }

  void check(const AppMsg& m, const std::string& got) {
    auto it = expect_.find(m.id);
    if (it == expect_.end()) return;
    bool ok = it->second.want == got;
    say("verify", "%s id=%llu : %s", it->second.what, (unsigned long long)m.id, ok ? "PASS" : "FAIL");
    if (!ok) ++testFail_; else ++testPass_;
    expect_.erase(it);
  }

  static std::string baseName(std::string n) {
    auto s = n.find_last_of("/\\");
    if (s != std::string::npos) n = n.substr(s + 1);
    if (n.empty() || n == "." || n == "..") n = "unnamed";
    return n;
  }

  void handle(const AppMsg& m) {
    bool isEcho = m.name == "echo";
    switch (m.type) {
      case M_CHAT: {
        std::string t = sanitizeUtf8(std::string(m.body.begin(), m.body.end()));
        if (isEcho) { check(m, std::string(m.body.begin(), m.body.end())); say("app", "echo of #%llu: %s", (unsigned long long)m.id, t.c_str()); }
        else {
          say("chat", "<%s> %s", sanitizeUtf8(m.name).c_str(), t.c_str());
          sendMsg(AppMsg{M_CHAT, m.id, nowMs(), "echo", m.body});
        }
        break;
      }
      case M_FILE:
      case M_BLOB: {
        auto d = sha256(m.body);
        std::string h = hex(d.data(), 32);
        if (m.type == M_FILE) {
          mkdir("received", 0755);
          std::string path = "received/" + baseName(m.name);
          std::ofstream f(path, std::ios::binary);
          f.write((const char*)m.body.data(), (std::streamsize)m.body.size());
          say("app", "received file %s (%zu bytes) sha256=%.16s...", path.c_str(), m.body.size(), h.c_str());
        } else say("app", "received blob (%zu bytes) sha256=%.16s...", m.body.size(), h.c_str());
        sendMsg(AppMsg{M_BLOBACK, m.id, nowMs(), "echo", toBytes(h)});
        break;
      }
      case M_BLOBACK: check(m, std::string(m.body.begin(), m.body.end())); break;
      case M_PING: sendMsg(AppMsg{M_PONG, m.id, m.ts, "echo", {}}); break;
      case M_PONG: say("app", "pong rtt=%.3f ms", (nowMs() - m.ts) / 1.0); break;
      default: break;
    }
  }

  void onUdp(uint32_t ip, uint16_t port, Bytes&& d) {
    std::string s = sanitizeUtf8(std::string(d.begin(), d.end()));
    say("udp", "datagram from %s:%u: %s", ipStr(ip).c_str(), port, s.c_str());
    if (s.rfind("echo:", 0) == 0) { if (cfg_.test && s == "echo:" + udpWant_) udpDone_ = true; }
    else tp_.sendUdp(ip, UDP_PORT, port, toBytes("echo:" + s));
  }

  // ---- automated two-machine test (client side) ----
  void runTests() {
    testStart_ = nowMs();
    say("test", "ICMP ping x3 (exercises ARP, L2 and L3)");
    for (int i = 1; i <= 3; i++) net_.ping(cfg_.peerIp, (uint16_t)i);
    udpWant_ = "udp-test-" + std::to_string(rng()() % 100000);
    tp_.sendUdp(cfg_.peerIp, UDP_PORT, UDP_PORT, toBytes(udpWant_));
    for (int i = 1; i <= 5; i++) {
      std::string t = "hello from the client #" + std::to_string(i) + " - h\xc3\xa9llo \xe2\x9c\x93";
      AppMsg m{M_CHAT, ++nextId_, nowMs(), "client", toBytes(t)};
      expect_[m.id] = {t, "chat"};
      sendMsg(m);
    }
    Bytes blob(256 * 1024);
    for (auto& x : blob) x = (uint8_t)rng()();
    AppMsg b{M_BLOB, ++nextId_, nowMs(), "client", blob};
    { auto d = sha256(blob); expect_[b.id] = {hex(d.data(), 32), "256KiB random blob"}; }
    sendMsg(b);
    std::string txt;
    while (txt.size() < 100 * 1024) txt += "The quick brown fox jumps over the lazy dog. 0123456789\n";
    AppMsg f{M_FILE, ++nextId_, nowMs(), "osi_test.txt", toBytes(txt)};
    { auto d = sha256(f.body); expect_[f.id] = {hex(d.data(), 32), "100KiB text file"}; }
    sendMsg(f);
  }
  void checkTests(uint64_t now) {
    if (!testStart_ || finishing_) return;
    bool done = pingsOk_ >= 3 && udpDone_ && expect_.empty();
    if (!done && now - lastRetry_ > 1000) {  // lossy wire: unreliable probes (ICMP/UDP) are simply re-sent
      lastRetry_ = now;
      for (int i = 1; i <= 3; i++) if (!(pingMask_ & (1u << i))) net_.ping(cfg_.peerIp, (uint16_t)i);
      if (!udpDone_) tp_.sendUdp(cfg_.peerIp, UDP_PORT, UDP_PORT, toBytes(udpWant_));
    }
    if (done || now - testStart_ > 90000) {
      testDone_ = done;
      finishing_ = true;
      if (!done) { testTimeout_ = true; say("test", "TIMEOUT: pings=%d udp=%d pending=%zu", pingsOk_, (int)udpDone_, expect_.size()); }
      say("test", "%s  (verified=%d failed=%d pings=%d udp=%s)", exitCode() == 0 ? "ALL PASSED" : "FAILED", testPass_, testFail_,
          pingsOk_, udpDone_ ? "ok" : "no");
      printStats();
      if (ses_) ses_->close();
      quitting_ = true; quitDeadline_ = now + 5000;
    }
  }

  Transport& tp_;
  Network& net_;
  Config cfg_;
  std::unique_ptr<Session> ses_;
  std::unique_ptr<Presentation> pres_;
  std::map<uint64_t, Expect> expect_;
  uint64_t nextId_ = 0, quitDeadline_ = 0, testStart_ = 0, lastRetry_ = 0;
  uint32_t pingMask_ = 0;
  int pingSeq_ = 100, pingsOk_ = 0, testPass_ = 0, testFail_ = 0;
  bool up_ = false, dead_ = false, finished_ = false, quitting_ = false, finishing_ = false, udpDone_ = false, testTimeout_ = false, testDone_ = false;
  std::string udpWant_;
};

// ============================================================================
// main: wire the layers together and run the event loop
// ============================================================================
static void usage() {
  printf(
      "usage: osi server|client [options]\n"
      "  --listen PORT     UDP port of the physical 'wire' (server default 9000, client default: any)\n"
      "  --peer HOST:PORT  other machine's wire address (required for client; server learns it)\n"
      "  --ip A.B.C.D      virtual IP of this node   (server 10.0.0.1, client 10.0.0.2)\n"
      "  --peer-ip A.B.C.D virtual IP of the other node\n"
      "  --app-port N      application port (default 7000)    --key SECRET (must match on both)\n"
      "  --loss PCT        simulate frame loss on transmit     --corrupt PCT  simulate bit flips\n"
      "  --mtu N           network MTU 100..1500 (small values force IP fragmentation)\n"
      "  --no-compress / --no-encrypt (must match on both)     --test (client: automated test)\n"
      "  --once            server exits after first session     -v  verbose per-layer log (stderr)\n");
}

int main(int argc, char** argv) {
  signal(SIGINT, [](int) { g_stop = 1; });
  signal(SIGPIPE, SIG_IGN);
  {  // known-answer test so a broken hash fails loudly
    auto d = sha256((const uint8_t*)"abc", 3);
    if (hex(d.data(), 32) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
      fprintf(stderr, "SHA-256 self-check failed\n");
      return 2;
    }
  }
  if (argc < 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) { usage(); return 2; }
  Config cfg;
  cfg.client = !strcmp(argv[1], "client");
  cfg.listenPort = cfg.client ? 0 : 9000;
  std::string ipS = cfg.client ? "10.0.0.2" : "10.0.0.1", pipS = cfg.client ? "10.0.0.1" : "10.0.0.2";
  for (int i = 2; i < argc; i++) {
    std::string a = argv[i];
    auto val = [&]() -> std::string { if (i + 1 >= argc) { usage(); exit(2); } return argv[++i]; };
    if (a == "--listen") cfg.listenPort = (uint16_t)atoi(val().c_str());
    else if (a == "--peer") cfg.peer = val();
    else if (a == "--ip") ipS = val();
    else if (a == "--peer-ip") pipS = val();
    else if (a == "--app-port") cfg.appPort = (uint16_t)atoi(val().c_str());
    else if (a == "--key") cfg.secret = val();
    else if (a == "--loss") cfg.loss = std::clamp(atoi(val().c_str()), 0, 90);
    else if (a == "--corrupt") cfg.corrupt = std::clamp(atoi(val().c_str()), 0, 90);
    else if (a == "--mtu") cfg.mtu = (size_t)std::clamp(atoi(val().c_str()), 100, 1500);
    else if (a == "--no-compress") cfg.compress = false;
    else if (a == "--no-encrypt") cfg.encrypt = false;
    else if (a == "--test") cfg.test = true;
    else if (a == "--once") cfg.once = true;
    else if (a == "-v") g_verbose = 1;
    else { usage(); return 2; }
  }
  if (!parseIp(ipS, cfg.ip) || !parseIp(pipS, cfg.peerIp)) { fprintf(stderr, "bad IP address\n"); return 2; }
  if (cfg.client && cfg.peer.empty()) { fprintf(stderr, "client needs --peer HOST:PORT\n"); return 2; }

  int rc = 0;
  {
    Physical phy;
    if (!phy.open(cfg.listenPort, cfg.peer)) return 1;
    phy.lossPct = cfg.loss; phy.corruptPct = cfg.corrupt;
    Mac mac = {0x02, 0x00, (uint8_t)(cfg.ip >> 24), (uint8_t)(cfg.ip >> 16), (uint8_t)(cfg.ip >> 8), (uint8_t)cfg.ip};
    DataLink dl(phy, mac, cfg.ip);
    Network net(dl, cfg.ip, cfg.mtu);
    Transport tp(net);
    App app(tp, net, cfg);
    phy.onFrame = [&](Buf&& f) { dl.rx(std::move(f)); };
    dl.onIp = [&](Buf&& p) { net.input(std::move(p)); };
    net.onProto = [&](uint8_t pr, uint32_t s, uint32_t d, Buf&& b) { tp.input(pr, s, d, std::move(b)); };
    app.lowerStats = [&] {
      return phy.stats() + "\n" + dl.stats() + "\n" + net.stats() + "\n" + tp.stats();
    };
    say("node", "%s ip=%s mac=%s wire-udp-port=%u mtu=%zu%s", argv[1], ipStr(cfg.ip).c_str(), macStr(mac).c_str(), phy.localPort(),
        cfg.mtu, cfg.loss || cfg.corrupt ? " (lossy wire simulation ON)" : "");
    app.start();

    bool stdinOpen = !cfg.test;
    std::string line;
    while (!g_stop && !app.finished()) {
      pollfd fds[2] = {{phy.fd(), POLLIN, 0}, {stdinOpen ? 0 : -1, POLLIN, 0}};
      ::poll(fds, 2, 10);
      phy.poll();
      if (stdinOpen && (fds[1].revents & (POLLIN | POLLHUP))) {
        if (std::getline(std::cin, line)) app.command(line);
        else stdinOpen = false;
      }
      uint64_t now = nowMs();
      dl.tick(now); net.tick(now); tp.tick(now); app.tick(now);
    }
    if (cfg.test || g_stop) app.printStats();
    rc = app.exitCode();
  }  // all layers destroyed here -> every Buf must be back in the pool
  if (!pool().report()) rc = 3;
  return rc;
}
