#ifndef HERO_H
#define HERO_H

#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <map>
#include <chrono>
#include <functional>

// Platform-specific socket includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    typedef int SOCKET;
#endif

namespace HERO {

// Protocol version
constexpr uint8_t VERSION = 1;

// Protocol flags
enum Flag : uint8_t {
    CONN = 0,  // Start connection (requires client public key)
    GIVE = 1,  // Send data (requires recipient key + payload)
    TAKE = 2,  // Request data/resources
    SEEN = 3,  // Acknowledge packet receipt
    STOP = 4   // Close connection
};

// Maximum packet size
constexpr size_t MAX_PACKET_SIZE = 65507;
constexpr int DEFAULT_TIMEOUT_MS = 5000;
constexpr int MAX_RETRIES = 3;

// Packet class
class Packet {
public:
    uint8_t flag;
    uint8_t version;
    uint16_t seq;
    std::vector<uint8_t> requirements;
    std::vector<uint8_t> payload;

    Packet() : flag(0), version(VERSION), seq(0) {}
    
    Packet(Flag f, uint16_t sequence) 
        : flag(f), version(VERSION), seq(sequence) {}
    
    Packet(Flag f, uint16_t sequence, const std::vector<uint8_t>& req, const std::vector<uint8_t>& data)
        : flag(f), version(VERSION), seq(sequence), requirements(req), payload(data) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer;
        
        uint16_t payload_len = static_cast<uint16_t>(payload.size());
        uint16_t req_len = static_cast<uint16_t>(requirements.size());
        
        buffer.reserve(8 + req_len + payload_len);
        
        buffer.push_back(flag);
        buffer.push_back(version);
        buffer.push_back((seq >> 8) & 0xFF);
        buffer.push_back(seq & 0xFF);
        buffer.push_back((payload_len >> 8) & 0xFF);
        buffer.push_back(payload_len & 0xFF);
        buffer.push_back((req_len >> 8) & 0xFF);
        buffer.push_back(req_len & 0xFF);
        
        buffer.insert(buffer.end(), requirements.begin(), requirements.end());
        buffer.insert(buffer.end(), payload.begin(), payload.end());
        
        return buffer;
    }

    static Packet deserialize(const std::vector<uint8_t>& data) {
        if (data.size() < 8) {
            throw std::runtime_error("Packet too small");
        }
        
        Packet pkt;
        pkt.flag = data[0];
        pkt.version = data[1];
        pkt.seq = (static_cast<uint16_t>(data[2]) << 8) | data[3];
        
        uint16_t payload_len = (static_cast<uint16_t>(data[4]) << 8) | data[5];
        uint16_t req_len = (static_cast<uint16_t>(data[6]) << 8) | data[7];
        
        if (data.size() < 8 + req_len + payload_len) {
            throw std::runtime_error("Packet data incomplete");
        }
        
        pkt.requirements.assign(data.begin() + 8, data.begin() + 8 + req_len);
        pkt.payload.assign(data.begin() + 8 + req_len, data.begin() + 8 + req_len + payload_len);
        
        return pkt;
    }

    static Packet makeConn(uint16_t seq, const std::vector<uint8_t>& client_pubkey) {
        return Packet(CONN, seq, client_pubkey, {});
    }

    static Packet makeGive(uint16_t seq, const std::vector<uint8_t>& recipient_key, 
                           const std::vector<uint8_t>& data) {
        return Packet(GIVE, seq, recipient_key, data);
    }

    static Packet makeTake(uint16_t seq, const std::vector<uint8_t>& resource_id = {}) {
        return Packet(TAKE, seq, resource_id, {});
    }

    static Packet makeSeen(uint16_t seq) {
        return Packet(SEEN, seq, {}, {});
    }

    static Packet makeStop(uint16_t seq) {
        return Packet(STOP, seq, {}, {});
    }

    bool isValid() const {
        return flag <= STOP && version == VERSION;
    }
};

// Socket wrapper with cross-platform support
class HeroSocket {
private:
    SOCKET sock;
    bool initialized;

    void setNonBlocking() {
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
#else
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
    }

public:
    HeroSocket() : sock(INVALID_SOCKET), initialized(false) {
#ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            throw std::runtime_error("Socket creation failed");
        }
        setNonBlocking();
        initialized = true;
    }

    ~HeroSocket() {
        if (sock != INVALID_SOCKET) {
#ifdef _WIN32
            closesocket(sock);
            WSACleanup();
#else
            close(sock);
#endif
        }
    }

    void bind(uint16_t port) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;
        
        if (::bind(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            throw std::runtime_error("Bind failed");
        }
    }

    bool send(const std::vector<uint8_t>& data, const std::string& host, uint16_t port) {
        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &dest.sin_addr);
        
        int sent = sendto(sock, (const char*)data.data(), data.size(), 0, 
                         (sockaddr*)&dest, sizeof(dest));
        return sent > 0;
    }

    bool recv(std::vector<uint8_t>& buffer, std::string& from_host, uint16_t& from_port) {
        buffer.resize(MAX_PACKET_SIZE);
        sockaddr_in from{};
        socklen_t fromlen = sizeof(from);
        
        int received = recvfrom(sock, (char*)buffer.data(), buffer.size(), 0,
                               (sockaddr*)&from, &fromlen);
        
        if (received > 0) {
            buffer.resize(received);
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));
            from_host = addr_str;
            from_port = ntohs(from.sin_port);
            return true;
        }
        return false;
    }

    SOCKET getSocket() const { return sock; }
};

// Client implementation
class HeroClient {
private:
    HeroSocket socket;
    uint16_t seq_num;
    std::string server_host;
    uint16_t server_port;
    bool connected;

public:
    HeroClient() : seq_num(0), server_port(0), connected(false) {}

    bool connect(const std::string& host, uint16_t port, const std::vector<uint8_t>& pubkey = {1,2,3,4}) {
        server_host = host;
        server_port = port;
        
        // Send CONN packet
        auto conn_pkt = Packet::makeConn(seq_num++, pubkey);
        auto data = conn_pkt.serialize();
        
        if (!socket.send(data, server_host, server_port)) {
            return false;
        }

        // Wait for SEEN acknowledgment
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(DEFAULT_TIMEOUT_MS)) {
            std::vector<uint8_t> buffer;
            std::string from_host;
            uint16_t from_port;
            
            if (socket.recv(buffer, from_host, from_port)) {
                try {
                    auto pkt = Packet::deserialize(buffer);
                    if (pkt.flag == SEEN) {
                        connected = true;
                        return true;
                    }
                } catch (...) {}
            }
        }
        
        return false;
    }

    bool send(const std::vector<uint8_t>& data, const std::vector<uint8_t>& recipient_key = {}) {
        if (!connected) return false;
        
        auto pkt = Packet::makeGive(seq_num++, recipient_key, data);
        return socket.send(pkt.serialize(), server_host, server_port);
    }

    // Send string directly
    bool send(const std::string& text, const std::vector<uint8_t>& recipient_key = {}) {
        return send(std::vector<uint8_t>(text.begin(), text.end()), recipient_key);
    }

    // Send C-string directly
    bool send(const char* text, const std::vector<uint8_t>& recipient_key = {}) {
        return send(std::string(text), recipient_key);
    }

    bool ping() {
        if (!connected) return false;
        
        auto pkt = Packet::makeTake(seq_num++);
        return socket.send(pkt.serialize(), server_host, server_port);
    }

    bool receive(Packet& out_packet, int timeout_ms = 100) {
        std::vector<uint8_t> buffer;
        std::string from_host;
        uint16_t from_port;
        
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(timeout_ms)) {
            if (socket.recv(buffer, from_host, from_port)) {
                try {
                    out_packet = Packet::deserialize(buffer);
                    
                    // Send SEEN acknowledgment
                    auto seen = Packet::makeSeen(out_packet.seq);
                    socket.send(seen.serialize(), from_host, from_port);
                    
                    return true;
                } catch (...) {}
            }
        }
        return false;
    }

    // Receive and get payload as string
    bool receiveString(std::string& out_text, int timeout_ms = 100) {
        Packet pkt;
        if (receive(pkt, timeout_ms)) {
            out_text = std::string(pkt.payload.begin(), pkt.payload.end());
            return true;
        }
        return false;
    }

    void disconnect() {
        if (connected) {
            auto stop_pkt = Packet::makeStop(seq_num++);
            socket.send(stop_pkt.serialize(), server_host, server_port);
            connected = false;
        }
    }

    bool isConnected() const { return connected; }
};

// Server implementation
class HeroServer {
private:
    HeroSocket socket;
    uint16_t port;
    bool running;
    
    struct Client {
        std::string host;
        uint16_t port;
        std::vector<uint8_t> pubkey;
        std::chrono::steady_clock::time_point last_seen;
    };
    
    std::map<std::string, Client> clients;

    std::string makeClientKey(const std::string& host, uint16_t port) {
        return host + ":" + std::to_string(port);
    }

public:
    HeroServer(uint16_t listen_port) : port(listen_port), running(false) {
        socket.bind(port);
    }

    void start() {
        running = true;
    }

    void stop() {
        running = false;
    }

    bool poll(std::function<void(const Packet&, const std::string&, uint16_t)> handler) {
        if (!running) return false;

        std::vector<uint8_t> buffer;
        std::string from_host;
        uint16_t from_port;

        if (socket.recv(buffer, from_host, from_port)) {
            try {
                auto pkt = Packet::deserialize(buffer);
                std::string client_key = makeClientKey(from_host, from_port);

                // Handle different packet types
                if (pkt.flag == CONN) {
                    // New connection
                    Client c;
                    c.host = from_host;
                    c.port = from_port;
                    c.pubkey = pkt.requirements;
                    c.last_seen = std::chrono::steady_clock::now();
                    clients[client_key] = c;
                    
                    // Send SEEN acknowledgment
                    auto seen = Packet::makeSeen(pkt.seq);
                    socket.send(seen.serialize(), from_host, from_port);
                } 
                else if (pkt.flag == STOP) {
                    // Disconnect
                    clients.erase(client_key);
                    auto seen = Packet::makeSeen(pkt.seq);
                    socket.send(seen.serialize(), from_host, from_port);
                }
                else {
                    // Update last seen
                    if (clients.count(client_key)) {
                        clients[client_key].last_seen = std::chrono::steady_clock::now();
                    }
                    
                    // Send SEEN acknowledgment
                    auto seen = Packet::makeSeen(pkt.seq);
                    socket.send(seen.serialize(), from_host, from_port);
                    
                    // Call handler
                    if (handler) {
                        handler(pkt, from_host, from_port);
                    }
                }
                
                return true;
            } catch (...) {}
        }
        
        return false;
    }

    void sendTo(const std::vector<uint8_t>& data, const std::string& host, uint16_t port) {
        auto pkt = Packet::makeGive(0, {}, data);
        socket.send(pkt.serialize(), host, port);
    }

    // Send string directly
    void sendTo(const std::string& text, const std::string& host, uint16_t port) {
        sendTo(std::vector<uint8_t>(text.begin(), text.end()), host, port);
    }

    // Send C-string directly
    void sendTo(const char* text, const std::string& host, uint16_t port) {
        sendTo(std::string(text), host, port);
    }

    // Reply to a packet easily
    void reply(const Packet& original_pkt, const std::vector<uint8_t>& response_data,
               const std::string& client_host, uint16_t client_port) {
        sendTo(response_data, client_host, client_port);
    }

    // Reply with string
    void reply(const Packet& original_pkt, const std::string& response_text,
               const std::string& client_host, uint16_t client_port) {
        sendTo(response_text, client_host, client_port);
    }

    int getClientCount() const {
        return clients.size();
    }

    bool isRunning() const { return running; }
};

} // namespace HERO

#endif // HERO_H
