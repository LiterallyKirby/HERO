#ifndef HERO_H
#define HERO_H

#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <map>
#include <chrono>
#include <functional>
#include <fstream>
#include <string>

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

// Helper functions for C++17 compatibility
inline bool endsWith(const std::string& str, const std::string& suffix) {
    if (suffix.length() > str.length()) return false;
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

inline bool startsWith(const std::string& str, const std::string& prefix) {
    if (prefix.length() > str.length()) return false;
    return str.compare(0, prefix.length(), prefix) == 0;
}

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

// Simple Web Server Extension
class HeroWebServer {
private:
    HeroServer server;
    std::string root_dir;

    std::string getMimeType(const std::string& path) {
        if (endsWith(path, ".html") || endsWith(path, ".htm")) return "text/html";
        if (endsWith(path, ".css")) return "text/css";
        if (endsWith(path, ".js")) return "application/javascript";
        if (endsWith(path, ".json")) return "application/json";
        if (endsWith(path, ".png")) return "image/png";
        if (endsWith(path, ".jpg") || endsWith(path, ".jpeg")) return "image/jpeg";
        if (endsWith(path, ".gif")) return "image/gif";
        if (endsWith(path, ".svg")) return "image/svg+xml";
        if (endsWith(path, ".txt")) return "text/plain";
        return "application/octet-stream";
    }

    std::string readFile(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return "";
        return std::string((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
    }

    void sendResponse(const std::string& content, const std::string& mime_type,
                     const std::string& host, uint16_t port) {
        std::string response = "HTTP/1.0 200 OK\r\n";
        response += "Content-Type: " + mime_type + "\r\n";
        response += "Content-Length: " + std::to_string(content.size()) + "\r\n\r\n";
        response += content;
        
        // Send in chunks if needed (max ~60KB per packet for safety)
        const size_t CHUNK_SIZE = 60000;
        for (size_t i = 0; i < response.size(); i += CHUNK_SIZE) {
            std::string chunk = response.substr(i, CHUNK_SIZE);
            server.sendTo(chunk, host, port);
        }
    }

    void send404(const std::string& host, uint16_t port) {
        std::string response = "HTTP/1.0 404 Not Found\r\n\r\n<h1>404 Not Found</h1>";
        server.sendTo(response, host, port);
    }

public:
    HeroWebServer(uint16_t port, const std::string& root_directory = ".")
        : server(port), root_dir(root_directory) {
        server.start();
    }

    void serve() {
        server.poll([&](const Packet& pkt, const std::string& host, uint16_t port) {
            std::string request(pkt.payload.begin(), pkt.payload.end());
            
            // Parse GET request
            if (startsWith(request, "GET ")) {
                size_t path_start = 4;
                size_t path_end = request.find(' ', path_start);
                if (path_end == std::string::npos) path_end = request.find('\r', path_start);
                if (path_end == std::string::npos) path_end = request.size();
                
                std::string path = request.substr(path_start, path_end - path_start);
                
                // Default to index.html
                if (path == "/" || path.empty()) {
                    path = "/index.html";
                }
                
                // Security: prevent directory traversal
                if (path.find("..") != std::string::npos) {
                    send404(host, port);
                    return;
                }
                
                std::string filepath = root_dir + path;
                std::string content = readFile(filepath);
                
                if (!content.empty()) {
                    sendResponse(content, getMimeType(path), host, port);
                } else {
                    send404(host, port);
                }
            }
        });
    }

    bool isRunning() const { return server.isRunning(); }
};

// Simple Web Client (Browser)
class HeroBrowser {
private:
    HeroClient client;
    
public:
    std::string get(const std::string& host, uint16_t port, const std::string& path = "/") {
        if (!client.isConnected()) {
            if (!client.connect(host, port)) {
                return "ERROR: Could not connect to server";
            }
        }
        
        // Send GET request
        std::string request = "GET " + path + " HTTP/1.0\r\n\r\n";
        client.send(request);
        
        // Receive response (handle multiple chunks)
        std::string full_response;
        std::string chunk;
        
        // Try to receive multiple chunks
        for (int i = 0; i < 10; i++) {  // Max 10 chunks
            if (client.receiveString(chunk, 1000)) {
                full_response += chunk;
            } else {
                break;  // No more data
            }
        }
        
        // Extract body from HTTP response
        size_t body_start = full_response.find("\r\n\r\n");
        if (body_start != std::string::npos) {
            return full_response.substr(body_start + 4);
        }
        
        return full_response;
    }
    
    void disconnect() {
        client.disconnect();
    }
};

} // namespace HERO

#endif // HERO_H
//
//
#ifndef HERO_DYNAMIC_WEB_H
#define HERO_DYNAMIC_WEB_H


#include <functional>
#include <sstream>

namespace HERO {

// Dynamic Web Server with persistent connections and event support
class HeroDynamicWebServer {
private:
    HeroServer server;
    std::string root_dir;
    
    struct WebClient {
        std::string host;
        uint16_t port;
        std::chrono::steady_clock::time_point last_seen;
        std::string current_path;
        bool waiting_for_updates;
    };
    
    std::map<std::string, WebClient> web_clients;
    std::map<std::string, std::function<std::string(const std::map<std::string, std::string>&)>> route_handlers;
    
    std::string makeClientKey(const std::string& host, uint16_t port) {
        return host + ":" + std::to_string(port);
    }

    std::string getMimeType(const std::string& path) {
        if (path.ends_with(".html") || path.ends_with(".htm")) return "text/html";
        if (path.ends_with(".css")) return "text/css";
        if (path.ends_with(".js")) return "application/javascript";
        if (path.ends_with(".json")) return "application/json";
        if (path.ends_with(".png")) return "image/png";
        if (path.ends_with(".jpg") || path.ends_with(".jpeg")) return "image/jpeg";
        if (path.ends_with(".gif")) return "image/gif";
        if (path.ends_with(".svg")) return "image/svg+xml";
        if (path.ends_with(".txt")) return "text/plain";
        return "application/octet-stream";
    }

    std::string readFile(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return "";
        return std::string((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
    }

    std::map<std::string, std::string> parseQueryString(const std::string& query) {
        std::map<std::string, std::string> params;
        std::istringstream qs(query);
        std::string pair;
        
        while (std::getline(qs, pair, '&')) {
            size_t eq = pair.find('=');
            if (eq != std::string::npos) {
                params[pair.substr(0, eq)] = pair.substr(eq + 1);
            }
        }
        return params;
    }

    void sendResponse(const std::string& content, const std::string& mime_type,
                     const std::string& host, uint16_t port, const std::string& extra_headers = "") {
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: " + mime_type + "\r\n";
        response += "Content-Length: " + std::to_string(content.size()) + "\r\n";
        if (!extra_headers.empty()) {
            response += extra_headers;
        }
        response += "\r\n" + content;
        
        const size_t CHUNK_SIZE = 60000;
        for (size_t i = 0; i < response.size(); i += CHUNK_SIZE) {
            std::string chunk = response.substr(i, CHUNK_SIZE);
            server.sendTo(chunk, host, port);
        }
    }

    void sendJSON(const std::string& json, const std::string& host, uint16_t port) {
        sendResponse(json, "application/json", host, port);
    }

    void send404(const std::string& host, uint16_t port) {
        std::string response = "HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>";
        server.sendTo(response, host, port);
    }

public:
    HeroDynamicWebServer(uint16_t port, const std::string& root_directory = ".")
        : server(port), root_dir(root_directory) {
        server.start();
    }

    // Register a dynamic route handler
    void route(const std::string& path, 
               std::function<std::string(const std::map<std::string, std::string>&)> handler) {
        route_handlers[path] = handler;
    }

    // Push updates to a specific client
    void pushToClient(const std::string& host, uint16_t port, const std::string& data) {
        std::string client_key = makeClientKey(host, port);
        if (web_clients.count(client_key)) {
            sendResponse(data, "text/event-stream", host, port, 
                        "Cache-Control: no-cache\r\nConnection: keep-alive\r\n");
        }
    }

    // Broadcast to all connected clients
    void broadcast(const std::string& data) {
        for (auto& [key, client] : web_clients) {
            if (client.waiting_for_updates) {
                pushToClient(client.host, client.port, data);
                client.waiting_for_updates = false;
            }
        }
    }

    // Broadcast JSON event
    void broadcastEvent(const std::string& event_name, const std::string& data) {
        std::string event_data = "event: " + event_name + "\ndata: " + data + "\n\n";
        broadcast(event_data);
    }

    void serve() {
        server.poll([&](const Packet& pkt, const std::string& host, uint16_t port) {
            std::string request(pkt.payload.begin(), pkt.payload.end());
            std::string client_key = makeClientKey(host, port);
            
            // Track client
            if (!web_clients.count(client_key)) {
                WebClient wc;
                wc.host = host;
                wc.port = port;
                wc.last_seen = std::chrono::steady_clock::now();
                wc.waiting_for_updates = false;
                web_clients[client_key] = wc;
            } else {
                web_clients[client_key].last_seen = std::chrono::steady_clock::now();
            }
            
            // Parse HTTP request
            if (request.starts_with("GET ") || request.starts_with("POST ")) {
                bool is_post = request.starts_with("POST ");
                size_t path_start = is_post ? 5 : 4;
                size_t path_end = request.find(' ', path_start);
                if (path_end == std::string::npos) path_end = request.find('\r', path_start);
                if (path_end == std::string::npos) path_end = request.size();
                
                std::string full_path = request.substr(path_start, path_end - path_start);
                
                // Split path and query string
                std::string path = full_path;
                std::string query;
                size_t q_pos = full_path.find('?');
                if (q_pos != std::string::npos) {
                    path = full_path.substr(0, q_pos);
                    query = full_path.substr(q_pos + 1);
                }
                
                auto params = parseQueryString(query);
                
                // Handle POST body
                if (is_post) {
                    size_t body_start = request.find("\r\n\r\n");
                    if (body_start != std::string::npos) {
                        std::string body = request.substr(body_start + 4);
                        auto body_params = parseQueryString(body);
                        params.insert(body_params.begin(), body_params.end());
                    }
                }
                
                web_clients[client_key].current_path = path;
                
                // Check for Server-Sent Events (SSE) connection
                if (path == "/events" || params.count("stream")) {
                    web_clients[client_key].waiting_for_updates = true;
                    // Send initial SSE response
                    sendResponse("", "text/event-stream", host, port,
                                "Cache-Control: no-cache\r\nConnection: keep-alive\r\n");
                    return;
                }
                
                // Check for dynamic route handler
                if (route_handlers.count(path)) {
                    std::string response = route_handlers[path](params);
                    sendResponse(response, "text/html", host, port);
                    return;
                }
                
                // Default to index.html for root
                if (path == "/" || path.empty()) {
                    path = "/index.html";
                }
                
                // Security: prevent directory traversal
                if (path.find("..") != std::string::npos) {
                    send404(host, port);
                    return;
                }
                
                // Serve static file
                std::string filepath = root_dir + path;
                std::string content = readFile(filepath);
                
                if (!content.empty()) {
                    sendResponse(content, getMimeType(path), host, port);
                } else {
                    send404(host, port);
                }
            }
        });
    }

    // Get number of connected clients
    int getClientCount() const {
        return web_clients.size();
    }
    
    // Clean up stale clients (not seen in 30 seconds)
    void cleanupStaleClients() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = web_clients.begin(); it != web_clients.end();) {
            if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_seen).count() > 30) {
                it = web_clients.erase(it);
            } else {
                ++it;
            }
        }
    }

    bool isRunning() const { return server.isRunning(); }
};

} // namespace HERO

#endif // HERO_DYNAMIC_WEB_H
