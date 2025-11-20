// herobrowser.cpp
#include "../include/HERO.h"
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

// Represents a single renderable element on the page
struct PageElement {
  SDL_Texture *texture;
  SDL_Rect rect; // Position relative to document top
  bool is_link;
  std::string href; // Target URL if link
  bool is_header;

  void destroy() {
    if (texture) {
      SDL_DestroyTexture(texture);
      texture = nullptr;
    }
  }
};

// Layout Engine & Renderer
// Layout Engine & Renderer
class RichRenderer {
private:
  SDL_Renderer *renderer;
  TTF_Font *font_body;
  TTF_Font *font_header;

  std::vector<PageElement> elements;
  int viewport_y;
  int total_content_height;

  const int LINE_HEIGHT = 24;
  const int HEADER_HEIGHT = 32;
  const int MARGIN_X = 15;
  const int MARGIN_Y = 15;

  // Helper to open fonts
  TTF_Font *loadFont(const std::vector<std::string> &candidates, int size) {
    for (const auto &p : candidates) {
      TTF_Font *f = TTF_OpenFont(p.c_str(), size);
      if (f)
        return f;
    }
    return nullptr;
  }

public:
  // FIX: Reordered initialization list to match declaration order (silences
  // warnings)
  RichRenderer(SDL_Renderer *r)
      : renderer(r), font_body(nullptr), font_header(nullptr), viewport_y(0),
        total_content_height(0) {
    std::vector<std::string> fonts = {
        "/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Regular.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "C:\\Windows\\Fonts\\arial.ttf", "/System/Library/Fonts/Helvetica.ttc"};

    font_body = loadFont(fonts, 16);
    font_header = loadFont(fonts, 24);

    if (!font_body)
      std::cerr << "Critical: Failed to load fonts." << std::endl;
  }

  ~RichRenderer() {
    clearPage();
    if (font_body)
      TTF_CloseFont(font_body);
    if (font_header)
      TTF_CloseFont(font_header);
  }

  void clearPage() {
    for (auto &el : elements)
      el.destroy();
    elements.clear();
    viewport_y = 0;
    total_content_height = 0;
  }

  void layoutPage(const std::string &raw_html, int window_width) {
    clearPage();

    SDL_Color colBlack = {0, 0, 0, 255};
    SDL_Color colBlue = {0, 0, 200, 255};
    SDL_Color colHeader = {50, 50, 50, 255};

    int cur_x = MARGIN_X;
    int cur_y = MARGIN_Y;
    int max_width = window_width - (MARGIN_X * 2);

    // FIX: Added 'rx' delimiter to raw string: R"rx(...)rx"
    // This prevents the compiler from thinking the quotes inside the regex end
    // the string.
    std::regex token_regex(
        R"rx((<a\s+href="([^"]+)">([^<]+)</a>)|(<h1>([^<]+)</h1>)|([^<]+))rx");

    auto begin =
        std::sregex_iterator(raw_html.begin(), raw_html.end(), token_regex);
    auto end = std::sregex_iterator();

    for (auto i = begin; i != end; ++i) {
      std::smatch match = *i;
      std::string text_content;
      bool is_link = false;
      bool is_h1 = false;
      std::string href = "";

      if (match[1].matched) { // It's a link
        href = match[2].str();
        text_content = match[3].str();
        is_link = true;
      } else if (match[4].matched) { // It's a H1
        text_content = match[5].str();
        is_h1 = true;
      } else { // Plain text
        text_content = match[6].str();
      }

      // Clean newlines/tabs from text
      std::replace(text_content.begin(), text_content.end(), '\n', ' ');
      std::replace(text_content.begin(), text_content.end(), '\r', ' ');
      std::replace(text_content.begin(), text_content.end(), '\t', ' ');

      if (std::all_of(text_content.begin(), text_content.end(), isspace)) {
        if (!elements.empty())
          cur_x += 5;
        continue;
      }

      std::stringstream ss(text_content);
      std::string word;
      while (ss >> word) {
        TTF_Font *useFont = is_h1 ? font_header : font_body;
        SDL_Color useColor = is_link ? colBlue : (is_h1 ? colHeader : colBlack);

        SDL_Surface *surf =
            TTF_RenderUTF8_Blended(useFont, word.c_str(), useColor);
        if (!surf)
          continue;

        if (cur_x + surf->w > max_width) {
          cur_x = MARGIN_X;
          cur_y += is_h1 ? HEADER_HEIGHT : LINE_HEIGHT;
        }

        SDL_Texture *tex = SDL_CreateTextureFromSurface(renderer, surf);

        PageElement el;
        el.texture = tex;
        el.rect = {cur_x, cur_y, surf->w, surf->h};
        el.is_link = is_link;
        el.href = href;
        el.is_header = is_h1;

        elements.push_back(el);

        cur_x += surf->w + 5;
        SDL_FreeSurface(surf);
      }

      if (is_h1) {
        cur_x = MARGIN_X;
        cur_y += HEADER_HEIGHT + 10;
      }
    }
    total_content_height = cur_y + 50;
  }

  // ... (rest of class methods checkClick, render, scroll, renderUIText remain
  // the same)

  std::string checkClick(int mouse_x, int mouse_y) {
    int doc_y = mouse_y + viewport_y;
    for (const auto &el : elements) {
      if (el.is_link) {
        if (mouse_x >= el.rect.x && mouse_x <= el.rect.x + el.rect.w &&
            doc_y >= el.rect.y && doc_y <= el.rect.y + el.rect.h) {
          return el.href;
        }
      }
    }
    return "";
  }

  void render(int window_height, int top_offset) {
    for (const auto &el : elements) {
      int screen_y = el.rect.y - viewport_y + top_offset;
      if (screen_y + el.rect.h < top_offset)
        continue;
      if (screen_y > window_height)
        break;

      SDL_Rect dest = {el.rect.x, screen_y, el.rect.w, el.rect.h};
      SDL_RenderCopy(renderer, el.texture, nullptr, &dest);

      if (el.is_link) {
        SDL_SetRenderDrawColor(renderer, 0, 0, 200, 255);
        SDL_RenderDrawLine(renderer, dest.x, dest.y + dest.h, dest.x + dest.w,
                           dest.y + dest.h);
      }
    }

    if (total_content_height > window_height) {
      float pct = (float)viewport_y / (total_content_height - window_height);
      int bar_h = 50;
      int bar_y =
          top_offset + (int)(pct * (window_height - top_offset - bar_h));
      SDL_Rect sb = {1024 - 10, bar_y, 5, bar_h};
      SDL_SetRenderDrawColor(renderer, 200, 200, 200, 255);
      SDL_RenderFillRect(renderer, &sb);
    }
  }

  void scroll(int delta) {
    viewport_y += delta;
    if (viewport_y < 0)
      viewport_y = 0;
  }

  void renderUIText(const std::string &text, int x, int y, SDL_Color color) {
    SDL_Surface *surface =
        TTF_RenderUTF8_Blended(font_body, text.c_str(), color);
    if (!surface)
      return;
    SDL_Texture *texture = SDL_CreateTextureFromSurface(renderer, surface);
    SDL_Rect dest = {x, y, surface->w, surface->h};
    SDL_RenderCopy(renderer, texture, nullptr, &dest);
    SDL_DestroyTexture(texture);
    SDL_FreeSurface(surface);
  }
};
class HEROBrowser {
private:
  SDL_Window *window;
  SDL_Renderer *renderer;
  RichRenderer *page_renderer;

  std::string url_bar_text;
  std::string status_message;
  bool running;
  bool url_input_active;
  uint32_t blink_timer;

  // History Stack
  std::vector<std::string> history;
  int history_index;

  const int WINDOW_WIDTH = 1024;
  const int WINDOW_HEIGHT = 768;
  const int URL_BAR_HEIGHT = 50;

  bool isHeroDomain(const std::string &url) {
    return url.find(".hero") != std::string::npos ||
           url.rfind("hero://", 0) == 0;
  }

  std::pair<std::string, uint16_t> parseHeroURL(const std::string &url) {
    std::regex hero_regex(R"(^(?:hero://)?([^/:]+)(?::(\d+))?)",
                          std::regex::icase);
    std::smatch match;
    if (std::regex_search(url, match, hero_regex)) {
      std::string host = match[1].str();
      uint16_t port = 8080;
      if (match.size() > 2 && match[2].matched) {
        try {
          port = static_cast<uint16_t>(std::stoi(match[2].str()));
        } catch (...) {
        }
      }
      return {host, port};
    }
    return {"localhost", 8080};
  }

  void loadPage(const std::string &url, bool pushHistory = true) {
    if (url.empty())
      return;

    status_message = "Loading " + url + "...";
    renderFrame(); // Force one render to show loading state

    std::string content;
    if (isHeroDomain(url)) {
      auto [host, port] = parseHeroURL(url);
      HERO::HeroBrowser browser;
      std::string resp = browser.get(host, port, "/");
      browser.disconnect();

      if (resp.rfind("ERROR:", 0) == 0) {
        content = "<h1>Connection Error</h1><p>" + resp + "</p>";
      } else {
        content = resp;
      }
    } else {
      content = "<h1>Protocol Mismatch</h1><p>Only <b>.hero</b> domains are "
                "supported.</p>";
    }

    // Update History
    if (pushHistory) {
      // Remove forward history if we branched
      if (history_index < (int)history.size() - 1) {
        history.resize(history_index + 1);
      }
      history.push_back(url);
      history_index = history.size() - 1;
    }

    url_bar_text = url;
    page_renderer->layoutPage(content, WINDOW_WIDTH);
    status_message = "Done.";
  }

  void goBack() {
    if (history_index > 0) {
      history_index--;
      loadPage(history[history_index], false);
    }
  }

  void goForward() {
    if (history_index < (int)history.size() - 1) {
      history_index++;
      loadPage(history[history_index], false);
    }
  }

  void handleInputEvents(SDL_Event &event) {
    if (event.type == SDL_TEXTINPUT && url_input_active) {
      url_bar_text += event.text.text;
    } else if (event.type == SDL_KEYDOWN) {
      // Shortcuts
      if (event.key.keysym.mod & KMOD_CTRL) {
        switch (event.key.keysym.sym) {
        case SDLK_v: // Paste
          if (SDL_HasClipboardText()) {
            char *text = SDL_GetClipboardText();
            if (text) {
              url_bar_text += text;
              SDL_free(text);
            }
          }
          break;
        case SDLK_l: // Focus Bar
          url_input_active = true;
          break;
        case SDLK_LEFT: // Back
          goBack();
          break;
        case SDLK_RIGHT: // Forward
          goForward();
          break;
        }
      }

      // Navigation
      if (event.key.keysym.sym == SDLK_RETURN) {
        url_input_active = false;
        loadPage(url_bar_text);
      } else if (event.key.keysym.sym == SDLK_BACKSPACE && url_input_active &&
                 !url_bar_text.empty()) {
        url_bar_text.pop_back();
      } else if (event.key.keysym.sym == SDLK_ESCAPE) {
        url_input_active = false;
      }
    } else if (event.type == SDL_MOUSEBUTTONDOWN) {
      if (event.button.y < URL_BAR_HEIGHT) {
        url_input_active = true;
      } else {
        url_input_active = false;
        // Check link click
        std::string target = page_renderer->checkClick(
            event.button.x, event.button.y - URL_BAR_HEIGHT);
        if (!target.empty()) {
          // Handle relative vs absolute roughly
          if (target.find("://") == std::string::npos &&
              target.find(".hero") == std::string::npos) {
            // very naive relative handling, just assumes root
            // In a real browser, we'd need current host context
            status_message = "Relative links not fully supported yet.";
          } else {
            loadPage(target);
          }
        }
      }
    } else if (event.type == SDL_MOUSEWHEEL) {
      page_renderer->scroll(-event.wheel.y * 30);
    }
  }

  void renderUI() {
    // URL Bar BG
    SDL_SetRenderDrawColor(renderer, 230, 230, 230, 255);
    SDL_Rect barRect = {0, 0, WINDOW_WIDTH, URL_BAR_HEIGHT};
    SDL_RenderFillRect(renderer, &barRect);

    // Border
    SDL_SetRenderDrawColor(renderer, 160, 160, 160, 255);
    SDL_RenderDrawLine(renderer, 0, URL_BAR_HEIGHT - 1, WINDOW_WIDTH,
                       URL_BAR_HEIGHT - 1);

    // URL Text
    SDL_Color txtCol = {0, 0, 0, 255};
    page_renderer->renderUIText(url_bar_text, 10, 15, txtCol);

    // Cursor (Blinking)
    if (url_input_active && (SDL_GetTicks() / 500) % 2 == 0) {
      int w_est = url_bar_text.length() * 9; // rough estimate
      SDL_Rect cursor = {10 + w_est, 15, 2, 20};
      SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
      SDL_RenderFillRect(renderer, &cursor);
    }

    // Status Bar
    SDL_SetRenderDrawColor(renderer, 245, 245, 245, 255);
    SDL_Rect statRect = {0, WINDOW_HEIGHT - 25, WINDOW_WIDTH, 25};
    SDL_RenderFillRect(renderer, &statRect);

    SDL_Color statCol = {100, 100, 100, 255};
    page_renderer->renderUIText(
        status_message + " | Hist: " + std::to_string(history_index + 1) + "/" +
            std::to_string(history.size()),
        10, WINDOW_HEIGHT - 22, statCol);
  }

public:
  HEROBrowser()
      : window(nullptr), renderer(nullptr), page_renderer(nullptr),
        running(false), url_input_active(false), history_index(-1) {}

  bool init() {
    if (SDL_Init(SDL_INIT_VIDEO) < 0)
      return false;
    if (TTF_Init() < 0)
      return false;

    window = SDL_CreateWindow(
        "HERO Browser v0.2", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        WINDOW_WIDTH, WINDOW_HEIGHT, SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE);
    if (!window)
      return false;

    renderer = SDL_CreateRenderer(
        window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer)
      return false;

    page_renderer = new RichRenderer(renderer);
    running = true;
    SDL_StartTextInput();

    // Load welcome page
    loadPage("localhost.hero:8080"); // Default

    return true;
  }

  void renderFrame() {
    SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
    SDL_RenderClear(renderer);

    page_renderer->render(WINDOW_HEIGHT - 25, URL_BAR_HEIGHT);
    renderUI();

    SDL_RenderPresent(renderer);
  }

  void run() {
    SDL_Event event;
    while (running) {
      while (SDL_PollEvent(&event)) {
        if (event.type == SDL_QUIT)
          running = false;
        else
          handleInputEvents(event);
      }
      renderFrame();
    }
    cleanup();
  }

  void cleanup() {
    delete page_renderer;
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    TTF_Quit();
    SDL_Quit();
  }
};

int main(int argc, char *argv[]) {
  HEROBrowser browser;
  if (browser.init())
    browser.run();
  return 0;
}
