#ifndef LOADER_CORE_H
#define LOADER_CORE_H

#include <string>
#include <cstdint>
#include <vector>

//
// loader_core.h
//
// This is the public-facing header file for the protection engine.
// It exposes the primary functions and data structures needed by the
// main protector GUI application to interface with the core logic.
// All internal VM logic, opcodes, and handlers are encapsulated
// within loader_core.cpp to maintain a clean public API.
//

/**
 * @struct ProtectorSettings
 * @brief Defines a set of configurable options for the protection process.
 * These settings can be adjusted from the main application UI to control
 * the obfuscation and security features applied to the target binary.
 */
struct ProtectorSettings {
    bool enable_junk_insertion = true;    ///< If true, junk opcodes will be inserted for obfuscation.
    bool enable_anti_debugging = true;    ///< If true, anti-debugging checks will be embedded in the loader.
    bool enable_anti_vm = true;           ///< If true, anti-virtual machine checks will be embedded.
    int junk_probability = 15;            ///< The chance (0-100) of inserting junk code per original instruction.
};

/**
 * @brief The main entry point for the virtualization process.
 *
 * This function takes a target DLL, reads the function at the specified
 * Relative Virtual Address (RVA), lifts it to a custom intermediate representation,
 * and then recompiles it into bytecode for the custom VM. Finally, it patches
p * the original DLL to redirect execution to the VM.
 *
 * @param dll_path The file path to the target DLL (e.g., "GameAssembly.dll").
 * @param func_rva The RVA of the function to be virtualized.
 * @param settings A struct containing the desired protection settings.
 */
void protect_function(const std::string& dll_path, uint64_t func_rva, const ProtectorSettings& settings);

/**
 * @brief Generates the final loader executable.
 *
 * This function creates a new executable file that contains the encrypted
 * DLL and metadata, along with the necessary logic to decrypt the data,

 * set up the custom VM, and run the virtualized code.
 *
 * @param protected_dll The path to the newly created protected (encrypted) DLL.
 * @param protected_meta The path to the newly created protected (encrypted) metadata file.
 * @param settings A struct containing the protection settings used.
 */
void generate_loader(const std::string& protected_dll, const std::string& protected_meta, const ProtectorSettings& settings);

/**
 * @brief A simple file encryption utility.
 *
 * This function reads a file, applies a basic encryption algorithm (in a real scenario,
 * this would be a strong, secure algorithm like AES-GCM), and writes the
 * encrypted content to an output file.
 *
 * @param input_path The path to the file to encrypt.
 * @param output_path The path where the encrypted file will be saved.
 * @return True if encryption was successful, false otherwise.
 */
bool encrypt_file(const std::string& input_path, const std::string& output_path);

/**
 * @brief Utility function to convert a 64-bit integer to a hexadecimal string.
 *
 * Useful for logging and displaying memory addresses and other large numbers in a
 * standardized, readable format.
 *
 * @param val The 64-bit unsigned integer to convert.
 * @return A string representing the value in hexadecimal (e.g., "0x123ABC").
 */
std::string to_hex_string(uint64_t val);

#endif // LOADER_CORE_H