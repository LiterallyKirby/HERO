#include "../../HERO.h"

int main() {
  HERO::HeroServer server(8080);
  server.start();

  while (true) {
    server.poll(
        [&](const HERO::Packet &pkt, const std::string &host, uint16_t port) {
          // Super easy!
          server.reply(pkt, "Message received!", host, port);
        });
  }
}
