#ifndef LOADER_CORE_H
#define LOADER_CORE_H

#include <string>
#include <cstdint>

// Configuration options for the protection process, exposed to the main UI.
struct ProtectorSettings {
    bool enable_junk_insertion = true;
    bool enable_anti_debugging = true;
    bool enable_anti_vm = true;
    int junk_probability = 15;
};

// Main function to virtualize a function within a DLL.
void protect_function(const std::string& dll_path, uint64_t func_rva, const ProtectorSettings& settings);

// Generates the final loader executable.
void generate_loader(const std::string& protected_dll, const std::string& protected_meta, const ProtectorSettings& settings);

// Simple file encryption utility.
bool encrypt_file(const std::string& input_path, const std::string& output_path);

// Utility to convert a 64-bit integer to a hexadecimal string for logging.
std::string to_hex_string(uint64_t val);

#endif // LOADER_CORE_H