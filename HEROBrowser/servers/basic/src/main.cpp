// test_server.cpp - A simple HERO web server to test the browser
#include "../include/HERO.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>

// Function to read the file content
std::string readFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return "<h1>404 File Not Found</h1>";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main() {
    std::cout << "Starting HERO Test Server on port 8080..." << std::endl;
    
    // Initialize server with port 8080 and root directory '.'
    HERO::HeroDynamicWebServer server(8080, ".");
    
    // ----------------------------------------------------
    // FIX 1: Explicitly map the root path "/" to index.html
    // ----------------------------------------------------
    server.route("/", 
        [](const std::map<std::string, std::string>& params) -> std::string {
            // Read index.html from the current directory
            std::string content = readFile("./index.html");
            
            // Check if file was read successfully
            if (content.find("404") != std::string::npos) {
                return "<h1>Welcome to the HERO Server! Create an index.html file to see content.</h1>";
            }
            
            // Return the HTML content
            return content;
        }
    );

    std::cout << "Server running! Try accessing it with:" << std::endl;
    std::cout << "  - HERO Browser: localhost.hero:8080" << std::endl;
    std::cout << "  - Direct: hero://localhost:8080" << std::endl;
    std::cout << "\nPress Ctrl+C to stop..." << std::endl;
    
    // ----------------------------------------------------
    // FIX 2: Correct the loop body to call server.serve()
    // ----------------------------------------------------
    while (server.isRunning()) {
        server.serve(); // This call handles incoming packets (requests)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return 0;
}
