//
// loader_core.h
//
// This is the central header file for the entire virtualization and protection engine.
// It defines all core data structures, constants, error codes, VM opcodes,
// and function prototypes used by the protector and the generated loader.
//
#ifndef LOADER_CORE_H
#define LOADER_CORE_H

// --- System and Standard Library Includes ---
#include <windows.h>
#include <commdlg.h>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <map>
#include <iostream>
#include <random>
#include <ctime>
#include <wincrypt.h>
#include <cstring>
#include <cstddef>
#include <bcrypt.h>
#include <array>
#include <psapi.h>
#include <imagehlp.h>
#include <sstream>
#include <winternl.h>
#include <xmmintrin.h>
#include <immintrin.h>
#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>
#include <stdexcept>
#include <iomanip>
#include <intrin.h>

// --- Preprocessor Definitions and Undefinitions ---
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif
#ifdef ERROR_STACK_OVERFLOW
#undef ERROR_STACK_OVERFLOW
#endif

// --- Type Definitions for Windows Internals ---
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// For NtQuerySystemInformation anti-debugging check
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemKernelDebuggerInformation = 0x23
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

// --- Debug Logging Macro ---
#ifdef _DEBUG
#define LOG_DEBUG(msg) OutputDebugStringA((std::string("[DEBUG] ") + msg + "\n").c_str())
#else
#define LOG_DEBUG(msg)
#endif

// --- Core Constants ---
const int NUM_REGISTERS = 16;
const int MAX_BYTECODE_SIZE = 16384;
const int STACK_SIZE_INITIAL = 4096;
const int VM_EXECUTION_TIMEOUT = 10000000;
const char* LOADER_SECTION_NAME = ".vmp";

// Obfuscation parameters
const int JUNK_INSERTION_PROBABILITY = 15;
const int MAX_JUNK_PER_INSTRUCTION = 3;
const int MAX_JUNK_INSERTIONS = 1000;
const int RANDOM_SEED_MODIFIER = 42;

// Alignment and precision constants
const int MEMORY_ALIGNMENT_REQUIREMENT = 16;
const int FPU_PRECISION_BITS = 53;
const int SSE_ALIGNMENT = 16;
const int AVX_ALIGNMENT = 32;

// Cryptography constants
const int AES_KEY_SIZE_BYTES = 32;
const int GCM_NONCE_SIZE_BYTES = 12;
const int GCM_TAG_SIZE_BYTES = 16;
const int AES_KEY_SIZE = 32; // Alias for legacy constants
const int NONCE_SIZE = 12;   // Alias for legacy constants
const int TAG_SIZE = 16;     // Alias for legacy constants

// --- Comprehensive Error Codes ---
enum class ProtectionError : int {
    SUCCESS = 0,
    // VM Execution Errors
    ERROR_INVALID_OPCODE = -1,
    ERROR_OUT_OF_BOUNDS = -2,
    ERROR_STACK_OVERFLOW = -3,
    ERROR_STACK_UNDERFLOW = -4,
    ERROR_DIVISION_BY_ZERO = -5,
    ERROR_MOD_BY_ZERO = -6,
    ERROR_INVALID_REGISTER = -7,
    ERROR_VM_HALT = -8,
    ERROR_INVALID_MEMORY = -9,
    ERROR_FLOAT_OVERFLOW = -10,
    ERROR_INVALID_INSTRUCTION_SIZE = -11,
    ERROR_UNSUPPORTED_ARCH = -13,
    ERROR_SSE_FAILURE = -14,
    ERROR_FPU_STACK_OVERFLOW = -15,
    ERROR_INVALID_OPERAND = -16,
    ERROR_ALIGNMENT_FAULT = -17,
    ERROR_PRIVILEGED_INSTRUCTION = -18,
    ERROR_PAGE_FAULT = -19,
    ERROR_GENERAL_PROTECTION = -20,
    ERROR_INTEGER_OVERFLOW = -21,
    ERROR_INTEGER_UNDERFLOW = -22,
    ERROR_FLOAT_UNDERFLOW = -23,
    ERROR_FLOAT_DENORMAL = -24,
    ERROR_FLOAT_INVALID_OP = -25,
    ERROR_FLOAT_PRECISION = -26,
    ERROR_FLOAT_STACK_CHECK = -27,
    ERROR_SSE_ALIGNMENT = -28,
    ERROR_SSE_INVALID_OP = -29,
    ERROR_AVX_ALIGNMENT = -30,
    ERROR_AVX_INVALID_OP = -31,
    // Protector Logic Errors
    ERROR_AES_FAILURE = -32,
    ERROR_RANDOM_FAILURE = -33,
    ERROR_MEMORY_ALLOCATION = -34,
    ERROR_FILE_IO = -35,
    ERROR_CONFIG = -39,
    ERROR_CRYPTO_FAILURE = -46,
    ERROR_DISASSEMBLY_FAILURE = -47,
    ERROR_RECOMPILE_FAILURE = -48,
    ERROR_PATCH_FAILURE = -49,
    ERROR_LOADER_GENERATION_FAILURE = -50,
    ERROR_INSUFFICIENT_RESOURCES = -55,
    // Anti-Debugging and Anti-Analysis Errors
    ERROR_KERNEL_DEBUGGER_DETECTED = -12,
    ERROR_VM_DETECTED = -56,
    ERROR_TAMPERING_DETECTED = -57,
    // Placeholder errors for future expansion
    ERROR_NETWORK = -36,
    ERROR_DATABASE = -37,
    ERROR_UI = -38,
    ERROR_LICENSE = -40,
    ERROR_AUTHENTICATION = -41,
    ERROR_AUTHORIZATION = -42,
    ERROR_UNKNOWN = -100
};

// --- Virtual Machine Opcodes ---
enum class Opcodes : uint16_t {
    NOP = 0x00, ADD = 0x01, SUB = 0x02, MUL = 0x03, DIV = 0x04, AND = 0x05, OR = 0x06,
    NOT = 0x07, SHL = 0x08, SHR = 0x09, XOR = 0x0A, LOAD = 0x0B, STORE = 0x0C, JMP = 0x0D,
    JZ = 0x0E, JNZ = 0x0F, JC = 0x10, JNC = 0x11, CMP = 0x12, INC = 0x13, DEC = 0x14,
    MOV = 0x15, LOAD_IMM = 0x16, PUSH = 0x17, POP = 0x18, CALL = 0x19, RET = 0x1A, IMUL = 0x1B,
    IDIV = 0x1C, SAR = 0x1D, ROL = 0x1E, ROR = 0x1F, TEST = 0x20, CMOVE = 0x21, CMOVNE = 0x22,
    LEA = 0x23, JBE = 0x24, JA = 0x25, JS = 0x26, JNS = 0x27, JO = 0x28, JNO = 0x29, JP = 0x2A,
    JNP = 0x2B, ADC = 0x2C, SBB = 0x2D, JLE = 0x2E, JG = 0x2F, NEG = 0x30, BSWAP = 0x31,
    POPCNT = 0x32, LZCNT = 0x33, TZCNT = 0x34, RCL = 0x35, RCR = 0x36, SHLD = 0x37, SHRD = 0x38,
    BT = 0x39, BTS = 0x3A, BTR = 0x3B, BTC = 0x3C, CMOVZ = 0x3D, CMOVNZ = 0x3E, SETZ = 0x3F,
    SETNZ = 0x40, SETC = 0x41, SETNC = 0x42, SETS = 0x43, SETNS = 0x44, SETO = 0x45, SETNO = 0x46,
    SETP = 0x47, SETNP = 0x48, SETBE = 0x49, SETA = 0x4A, SETLE = 0x4B, SETG = 0x4C, CMOVBE = 0x4D,
    CMOVA = 0x4E, CMOVS = 0x4F, CMOVNS = 0x50, CMOVO = 0x51, CMOVNO = 0x52, CMOVP = 0x53,
    CMOVNP = 0x54, CMOVLE = 0x55, CMOVG = 0x56, BSF = 0x57, BSR = 0x58, MOD = 0x59, IMOD = 0x5A,
    ADD32 = 0x5B, SUB32 = 0x5C, MUL32 = 0x5D, DIV32 = 0x5E, IMUL32 = 0x5F, IDIV32 = 0x60,
    MOD32 = 0x61, IMOD32 = 0x62, FADD = 0x63, FSUB = 0x64, FMUL = 0x65, FDIV = 0x66, FLD = 0x67,
    FST = 0x68, FCMP = 0x69, PADDD = 0x6A, PSUBD = 0x6B, PMULD = 0x6C, PDIVD = 0x6D,
    MOVDQA = 0x6E, PCMPEQD = 0x6F, PAND = 0x70, POR = 0x71, PXOR = 0x72, PSLLD = 0x73,
    PSRLD = 0x74, PSLLQ = 0x75, PSRLQ = 0x76, MOVDQU = 0x77, CVTSI2SD = 0x78, CVTSD2SI = 0x79,
    SQRTSD = 0x7A, MINSD = 0x7B, MAXSD = 0x7C, ANDPD = 0x7D, ORPD = 0x7E, XORPD = 0x7F,
    BLENDPD = 0x80, ROUNDPD = 0x81, VADDPD = 0x82, VSUBPD = 0x83, VMULPD = 0x84, VDIVPD = 0x85,
    VMOVAPD = 0x86, VCMP_PD = 0x87, VBROADCASTSD = 0x88, VPERMILPD = 0x89, VFMSUBADDPD = 0x8A,
    VMASKMOVPD = 0x8B, VGATHERDPD = 0x8C, VSCATTERDPD = 0x8D, VAESENC = 0x8E, VAESDEC = 0x8F,
    VPCLMULQDQ = 0x90, VPCMPEQD = 0x91, VPSHUFD = 0x92, VINSERTF128 = 0x93, VEXTRACTF128 = 0x94,
    VPERM2F128 = 0x95, VBLENDVPD = 0x96, PUSHF = 0x97, POPF = 0x98, CPUID = 0x99, RDTSC = 0x9A,
    XCHG = 0x9B, CLD = 0x9C, STD = 0x9D, CLI = 0x9E, STI = 0x9F, HLT = 0xA0, INT = 0xA1,
    IRET = 0xA2, LOOP = 0xA3, LOOPE = 0xA4, LOOPNE = 0xA5, OP_IN = 0xA6, OP_OUT = 0xA7,
    LAHF = 0xA8, SAHF = 0xA9, CLTS = 0xAA, LGDT = 0xAB, SGDT = 0xAC, LIDT = 0xAD, SIDT = 0xAE,
    LMSW = 0xAF, SMSW = 0xB0, RDMSR = 0xB1, WRMSR = 0xB2, RDPMC = 0xB3, RSM = 0xB4, UD2 = 0xB5,
    EMMS = 0xB6, MOVD = 0xB7, MOVQ = 0xB8, PACKSSWB = 0xB9, PACKSSDW = 0xBA, PACKUSWB = 0xBB,
    MMX_PADDQ = 0xBC, MMX_PADDB = 0xBD, MMX_PADDW = 0xBE, MMX_PADDD = 0xBF, MMX_PSUBB = 0xC0,
    MMX_PSUBW = 0xC1, MMX_PSUBD = 0xC2, MMX_PSUBQ = 0xC3, PMADDWD = 0xC4, PMULHW = 0xC5,
    PMULLW = 0xC6, PAVGB = 0xC7, PAVGW = 0xC8, PMINUB = 0xC9, PMAXUB = 0xCA, PMINSW = 0xCB,
    PMAXSW = 0xCC, PSADBW = 0xCD, PSHUFW = 0xCE, MASKMOVQ = 0xCF, MOVNTQ = 0xD0, PANDN = 0xD1,
    PCMPGTB = 0xD2, PCMPGTW = 0xD3, PCMPGTD = 0xD4, PEXTRW = 0xD5, PINSRW = 0xD6, PMADDUBSW = 0xD7,
    PMAXSD = 0xD8, PMINSD = 0xD9, PMULUDQ = 0xDA, PSHUFB = 0xDB, PSIGNB = 0xDC, PSIGNW = 0xDD,
    PSIGND = 0xDE, PSUBUSB = 0xDF, PSUBUSW = 0xE0, PSRLW = 0xE1, PSRAW = 0xE2, PSLLW = 0xE3,
    PSUBSB = 0xE4, PSUBSW = 0xE5, PUNPCKLBW = 0xE6, PUNPCKLWD = 0xE7, PUNPCKLDQ = 0xE8,
    PUNPCKHBW = 0xE9, PUNPCKHWD = 0xEA, PUNPCKHDQ = 0xEB, MOVD_EXT = 0xEC, MOVQ_EXT = 0xED,
    PMOVMSKB = 0xEE, PMULHRSW = 0xEF, PSHUFLW = 0xF0, PSHUFHW = 0xF1, PSLLDQ = 0xF2,
    PSRLDQ = 0xF3, PTEST = 0xF4, VADDPS = 0xF5, VSUBPS = 0xF6, VMULPS = 0xF7, VDIVPS = 0xF8,
    VANDPS = 0xF9, VORPS = 0xFA, VXORPS = 0xFB, VBLENDPS = 0xFC, VMINPS = 0xFD, VMAXPS = 0xFE,
    EXIT = 0xFF,
    // Junk Opcodes
    JUNK1 = 0x100, JUNK2 = 0x101, JUNK3 = 0x102, JUNK4 = 0x103, JUNK5 = 0x104,
    JUNK6 = 0x105, JUNK7 = 0x106, JUNK8 = 0x107, JUNK9 = 0x108, JUNK10 = 0x109,
    JUNK11 = 0x10A, JUNK12 = 0x10B, JUNK13 = 0x10C, JUNK14 = 0x10D, JUNK15 = 0x10E,
    JUNK16 = 0x10F, JUNK17 = 0x110, JUNK18 = 0x111, JUNK19 = 0x112, JUNK20 = 0x113
};

// --- Core Data Structures ---

/**
 * @struct VMFlags
 * @brief Defines the state of the virtual CPU's arithmetic and control flags.
 */
struct VMFlags {
    bool zero = false;     ///< Zero Flag (ZF): Set if the result of an operation is zero.
    bool carry = false;    ///< Carry Flag (CF): Set on unsigned overflow.
    bool sign = false;     ///< Sign Flag (SF): Set if the result is negative (MSB is 1).
    bool overflow = false; ///< Overflow Flag (OF): Set on signed overflow.
    bool parity = false;   ///< Parity Flag (PF): Set if the number of set bits in the result is even.
};

/**
 * @struct u128
 * @brief Represents a 128-bit value, aligned to 16 bytes for SSE/AVX operations.
 */
struct alignas(16) u128 {
    uint64_t low;          ///< The lower 64 bits of the value.
    uint64_t high;         ///< The upper 64 bits of the value.
};

/**
 * @struct VMContext
 * @brief The complete context of the virtual machine at any point in time.
 * This structure holds all state necessary to execute virtualized code.
 */
struct VMContext {
    uint64_t regs[NUM_REGISTERS];       ///< General-purpose registers (R0-R15).
    u128 xmm_regs[NUM_REGISTERS];       ///< 128-bit SSE/AVX registers (XMM0-XMM15).
    uint8_t* ip;                        ///< Instruction Pointer: points into the VM bytecode.
    std::vector<uint8_t> stack;         ///< The VM's private stack memory.
    size_t sp;                          ///< Stack Pointer: current top of the stack.
    VMFlags flags;                      ///< Emulated CPU flags.
    bool running;                       ///< VM execution state (true = run, false = halt).
    ProtectionError last_error;         ///< Stores the code of the last error that occurred.
};

/**
 * @struct IRInstruction
 * @brief A simple Intermediate Representation (IR) for a single assembly instruction.
 * This is used when lifting native code into a format the recompiler can understand.
 */
struct IRInstruction {
    Opcodes opcode;                     ///< The VM opcode this instruction maps to.
    std::vector<std::string> operands;  ///< String representations of the original operands.
    uint64_t original_address;          ///< The address of the instruction in the original binary.
    size_t size;                        ///< The size of the original instruction in bytes.
};

/**
 * @struct AesGcmKey
 * @brief Holds handles for AES-GCM cryptography using the Windows CNG API.
 */
struct AesGcmKey {
    BCRYPT_ALG_HANDLE algHandle = NULL; ///< Handle to the CNG algorithm provider.
    BCRYPT_KEY_HANDLE keyHandle = NULL; ///< Handle to the specific encryption key.
};

/**
 * @struct ProtectorSettings
 * @brief Configuration options for the protection process.
 */
struct ProtectorSettings {
    bool enable_junk_insertion = true;    ///< If true, junk opcodes will be inserted for obfuscation.
    bool enable_anti_debugging = true;    ///< If true, anti-debugging checks will be embedded in the loader.
    bool enable_anti_vm = true;           ///< If true, anti-virtual machine checks will be embedded.
    int junk_probability = JUNK_INSERTION_PROBABILITY; ///< The chance (0-100) of inserting junk code.
};

// --- Function Prototypes ---

// Section 1: Core Protection Workflow
void protect_function(const std::string& dll_path, uint64_t func_rva, const ProtectorSettings& settings);
void generate_loader(const std::string& protected_dll, const std::string& protected_meta, const ProtectorSettings& settings);
std::string generate_loader_source(const std::string& protected_dll, const std::string& protected_meta, const ProtectorSettings& settings);

// Section 2: Cryptography & Key Management
bool aesgcm_init(AesGcmKey& ctx, const BYTE* key, DWORD keyLen);
bool aesgcm_encrypt(AesGcmKey& ctx, const BYTE* pt, DWORD ptLen, const BYTE* iv, DWORD ivLen, std::vector<BYTE>& ct_out, std::vector<BYTE>& tag_out);
bool aesgcm_decrypt(AesGcmKey& ctx, const BYTE* ct, DWORD ctLen, const BYTE* iv, DWORD ivLen, const BYTE* tag, DWORD tagLen, std::vector<BYTE>& pt_out);
bool encrypt_file(const std::string& input_path, const std::string& output_path);
bool decrypt_file(const std::string& input_path, std::vector<uint8_t>& data_out);
void get_key(uint8_t key[AES_KEY_SIZE_BYTES]);
std::vector<uint8_t> generate_key_bytecode();

// Section 3: PE File & Memory Manipulation
bool patch_binary(const std::string& dll_path, uint64_t func_rva, const std::vector<uint8_t>& vm_bytecode);
HMODULE LoadLibraryMemory(const void* raw_data, size_t size);
PIMAGE_NT_HEADERS GetNtHeaders(LPVOID image_base);
PIMAGE_SECTION_HEADER FindSection(PIMAGE_NT_HEADERS nt_headers, const char* section_name);
DWORD RvaToOffset(PIMAGE_NT_HEADERS nt_headers, DWORD rva);
bool AddSectionToPe(const std::string& file_path, const char* section_name, DWORD size_of_section, PVOID section_data);

// Section 4: Disassembly and Recompilation
std::vector<std::string> disassemble_function(const uint8_t* buffer, size_t length, uint64_t runtime_address);
std::vector<IRInstruction> lift_to_ir(const std::vector<std::string>& disasm);
std::vector<uint8_t> recompile_to_vm(const std::vector<IRInstruction>& ir, const ProtectorSettings& settings);
std::map<std::string, uint8_t> get_reg_map();

// Section 5: VM Execution Core
using Handler = void (*)(VMContext* ctx, uint8_t* instr);
extern Handler g_handlers[0x114]; // Size must match number of opcodes
void bind_handlers();
void run_vm(VMContext* ctx, uint64_t max_steps = VM_EXECUTION_TIMEOUT);
void InitVM(VMContext& ctx, uint8_t* data, size_t data_size, std::ostream* log = nullptr);

// Section 6: Utilities
bool file_exists(const std::string& path);
std::vector<uint8_t> read_file_bytes(const std::string& path);
bool write_file_bytes(const std::string& path, const std::vector<uint8_t>& data);
std::string to_hex_string(uint64_t val);
double u64_to_double(uint64_t u);
uint64_t double_to_u64(double d);
bool parity_even(uint64_t x);

// Section 7: Anti-Analysis and Anti-Debugging Techniques
bool IsKernelDebuggerPresent(); // Using NtQuerySystemInformation
bool CheckRemoteDebuggerPresent(); // Using CheckRemoteDebuggerPresent
bool IsDebuggerPresentPEB(); // Manual check of PEB->BeingDebugged flag
bool CheckNtGlobalFlagPEB(); // Manual check of PEB->NtGlobalFlag
bool CheckHardwareBreakpoints(); // Using GetThreadContext and DR registers
bool CheckTimingAttack(); // Using RDTSC to detect debugger latency
bool CheckForVmware(); // Check for VMWare artifacts (e.g., MAC address, device names)
bool CheckForVirtualBox(); // Check for VirtualBox artifacts
bool CheckForSandboxie(); // Check for Sandboxie DLL
bool CheckForWireshark(); // Check if a common analysis tool is running
bool ObscureModuleNames(); // Hide module names in the PEB
void ErasePeHeadersFromMemory(); // Nuke PE headers of the loaded module to hinder dumping

// --- VM Opcode Handlers (Complete Prototype List) ---

// This section declares a handler function for every single opcode defined in the Opcodes enum.
// This ensures type safety and allows the dispatcher to be a simple array lookup.

// Basic Arithmetic and Logic
void handle_nop(VMContext* ctx, uint8_t* instr);
void handle_add(VMContext* ctx, uint8_t* instr);
void handle_sub(VMContext* ctx, uint8_t* instr);
void handle_mul(VMContext* ctx, uint8_t* instr);
void handle_div(VMContext* ctx, uint8_t* instr);
void handle_and(VMContext* ctx, uint8_t* instr);
void handle_or(VMContext* ctx, uint8_t* instr);
void handle_not(VMContext* ctx, uint8_t* instr);
void handle_shl(VMContext* ctx, uint8_t* instr);
void handle_shr(VMContext* ctx, uint8_t* instr);
void handle_xor(VMContext* ctx, uint8_t* instr);
void handle_imul(VMContext* ctx, uint8_t* instr);
void handle_idiv(VMContext* ctx, uint8_t* instr);
void handle_sar(VMContext* ctx, uint8_t* instr);
void handle_rol(VMContext* ctx, uint8_t* instr);
void handle_ror(VMContext* ctx, uint8_t* instr);
void handle_neg(VMContext* ctx, uint8_t* instr);
void handle_inc(VMContext* ctx, uint8_t* instr);
void handle_dec(VMContext* ctx, uint8_t* instr);
void handle_adc(VMContext* ctx, uint8_t* instr);
void handle_sbb(VMContext* ctx, uint8_t* instr);

// Memory and Data Movement
void handle_load(VMContext* ctx, uint8_t* instr);
void handle_store(VMContext* ctx, uint8_t* instr);
void handle_mov(VMContext* ctx, uint8_t* instr);
void handle_load_imm(VMContext* ctx, uint8_t* instr);
void handle_lea(VMContext* ctx, uint8_t* instr);
void handle_xchg(VMContext* ctx, uint8_t* instr);
void handle_bswap(VMContext* ctx, uint8_t* instr);

// Stack Operations
void handle_push(VMContext* ctx, uint8_t* instr);
void handle_pop(VMContext* ctx, uint8_t* instr);
void handle_pushf(VMContext* ctx, uint8_t* instr);
void handle_popf(VMContext* ctx, uint8_t* instr);

// Control Flow
void handle_jmp(VMContext* ctx, uint8_t* instr);
void handle_jz(VMContext* ctx, uint8_t* instr);
void handle_jnz(VMContext* ctx, uint8_t* instr);
void handle_jc(VMContext* ctx, uint8_t* instr);
void handle_jnc(VMContext* ctx, uint8_t* instr);
void handle_jbe(VMContext* ctx, uint8_t* instr);
void handle_ja(VMContext* ctx, uint8_t* instr);
void handle_js(VMContext* ctx, uint8_t* instr);
void handle_jns(VMContext* ctx, uint8_t* instr);
void handle_jo(VMContext* ctx, uint8_t* instr);
void handle_jno(VMContext* ctx, uint8_t* instr);
void handle_jp(VMContext* ctx, uint8_t* instr);
void handle_jnp(VMContext* ctx, uint8_t* instr);
void handle_jle(VMContext* ctx, uint8_t* instr);
void handle_jg(VMContext* ctx, uint8_t* instr);
void handle_call(VMContext* ctx, uint8_t* instr);
void handle_ret(VMContext* ctx, uint8_t* instr);
void handle_loop(VMContext* ctx, uint8_t* instr);
void handle_loope(VMContext* ctx, uint8_t* instr);
void handle_loopne(VMContext* ctx, uint8_t* instr);

// Comparison and Testing
void handle_cmp(VMContext* ctx, uint8_t* instr);
void handle_test(VMContext* ctx, uint8_t* instr);
void handle_bt(VMContext* ctx, uint8_t* instr);
void handle_bts(VMContext* ctx, uint8_t* instr);
void handle_btr(VMContext* ctx, uint8_t* instr);
void handle_btc(VMContext* ctx, uint8_t* instr);

// Conditional Moves
void handle_cmove(VMContext* ctx, uint8_t* instr);
void handle_cmovne(VMContext* ctx, uint8_t* instr);
void handle_cmovz(VMContext* ctx, uint8_t* instr);
void handle_cmovnz(VMContext* ctx, uint8_t* instr);
void handle_cmovbe(VMContext* ctx, uint8_t* instr);
void handle_cmova(VMContext* ctx, uint8_t* instr);
void handle_cmovs(VMContext* ctx, uint8_t* instr);
void handle_cmovns(VMContext* ctx, uint8_t* instr);
void handle_cmovo(VMContext* ctx, uint8_t* instr);
void handle_cmovno(VMContext* ctx, uint8_t* instr);
void handle_cmovp(VMContext* ctx, uint8_t* instr);
void handle_cmovnp(VMContext* ctx, uint8_t* instr);
void handle_cmovle(VMContext* ctx, uint8_t* instr);
void handle_cmovg(VMContext* ctx, uint8_t* instr);

// Set-Byte on Condition
void handle_setz(VMContext* ctx, uint8_t* instr);
void handle_setnz(VMContext* ctx, uint8_t* instr);
void handle_setc(VMContext* ctx, uint8_t* instr);
void handle_setnc(VMContext* ctx, uint8_t* instr);
void handle_sets(VMContext* ctx, uint8_t* instr);
void handle_setns(VMContext* ctx, uint8_t* instr);
void handle_seto(VMContext* ctx, uint8_t* instr);
void handle_setno(VMContext* ctx, uint8_t* instr);
void handle_setp(VMContext* ctx, uint8_t* instr);
void handle_setnp(VMContext* ctx, uint8_t* instr);
void handle_setbe(VMContext* ctx, uint8_t* instr);
void handle_seta(VMContext* ctx, uint8_t* instr);
void handle_setle(VMContext* ctx, uint8_t* instr);
void handle_setg(VMContext* ctx, uint8_t* instr);

// Bit Manipulation
void handle_popcnt(VMContext* ctx, uint8_t* instr);
void handle_lzcnt(VMContext* ctx, uint8_t* instr);
void handle_tzcnt(VMContext* ctx, uint8_t* instr);
void handle_rcl(VMContext* ctx, uint8_t* instr);
void handle_rcr(VMContext* ctx, uint8_t* instr);
void handle_shld(VMContext* ctx, uint8_t* instr);
void handle_shrd(VMContext* ctx, uint8_t* instr);
void handle_bsf(VMContext* ctx, uint8_t* instr);
void handle_bsr(VMContext* ctx, uint8_t* instr);

// 32-bit Operations
void handle_mod(VMContext* ctx, uint8_t* instr);
void handle_imod(VMContext* ctx, uint8_t* instr);
void handle_add32(VMContext* ctx, uint8_t* instr);
void handle_sub32(VMContext* ctx, uint8_t* instr);
void handle_mul32(VMContext* ctx, uint8_t* instr);
void handle_div32(VMContext* ctx, uint8_t* instr);
void handle_imul32(VMContext* ctx, uint8_t* instr);
void handle_idiv32(VMContext* ctx, uint8_t* instr);
void handle_mod32(VMContext* ctx, uint8_t* instr);
void handle_imod32(VMContext* ctx, uint8_t* instr);

// FPU (Floating Point) Operations
void handle_fadd(VMContext* ctx, uint8_t* instr);
void handle_fsub(VMContext* ctx, uint8_t* instr);
void handle_fmul(VMContext* ctx, uint8_t* instr);
void handle_fdiv(VMContext* ctx, uint8_t* instr);
void handle_fld(VMContext* ctx, uint8_t* instr);
void handle_fst(VMContext* ctx, uint8_t* instr);
void handle_fcmp(VMContext* ctx, uint8_t* instr);

// SSE/SSE2 Operations
void handle_paddd(VMContext* ctx, uint8_t* instr);
void handle_psubd(VMContext* ctx, uint8_t* instr);
void handle_pmuld(VMContext* ctx, uint8_t* instr);
void handle_pdivd(VMContext* ctx, uint8_t* instr); // Note: No direct SSE instruction for this
void handle_movdqa(VMContext* ctx, uint8_t* instr);
void handle_movdqu(VMContext* ctx, uint8_t* instr);
void handle_pcmpeqd(VMContext* ctx, uint8_t* instr);
void handle_pand(VMContext* ctx, uint8_t* instr);
void handle_por(VMContext* ctx, uint8_t* instr);
void handle_pxor(VMContext* ctx, uint8_t* instr);
void handle_pslld(VMContext* ctx, uint8_t* instr);
void handle_psrld(VMContext* ctx, uint8_t* instr);
void handle_psllq(VMContext* ctx, uint8_t* instr);
void handle_psrlq(VMContext* ctx, uint8_t* instr);
void handle_cvtsi2sd(VMContext* ctx, uint8_t* instr);
void handle_cvtsd2si(VMContext* ctx, uint8_t* instr);
void handle_sqrtsd(VMContext* ctx, uint8_t* instr);
void handle_minsd(VMContext* ctx, uint8_t* instr);
void handle_maxsd(VMContext* ctx, uint8_t* instr);
void handle_andpd(VMContext* ctx, uint8_t* instr);
void handle_orpd(VMContext* ctx, uint8_t* instr);
void handle_xorpd(VMContext* ctx, uint8_t* instr);
void handle_blendpd(VMContext* ctx, uint8_t* instr);
void handle_roundpd(VMContext* ctx, uint8_t* instr);

// AVX Operations
void handle_vaddpd(VMContext* ctx, uint8_t* instr);
void handle_vsubpd(VMContext* ctx, uint8_t* instr);
void handle_vmulpd(VMContext* ctx, uint8_t* instr);
void handle_vdivpd(VMContext* ctx, uint8_t* instr);
void handle_vmovapd(VMContext* ctx, uint8_t* instr);
void handle_vcmp_pd(VMContext* ctx, uint8_t* instr);
void handle_vbroadcastsd(VMContext* ctx, uint8_t* instr);
void handle_vpermilpd(VMContext* ctx, uint8_t* instr);
void handle_vfmsubaddpd(VMContext* ctx, uint8_t* instr);
void handle_vmaskmovpd(VMContext* ctx, uint8_t* instr);
void handle_vgatherdpd(VMContext* ctx, uint8_t* instr);
void handle_vscatterdpd(VMContext* ctx, uint8_t* instr);
void handle_vaesenc(VMContext* ctx, uint8_t* instr);
void handle_vaesdec(VMContext* ctx, uint8_t* instr);
void handle_vpclmulqdq(VMContext* ctx, uint8_t* instr);
void handle_vpcmpeqd(VMContext* ctx, uint8_t* instr);
void handle_vpshufd(VMContext* ctx, uint8_t* instr);
void handle_vinsertf128(VMContext* ctx, uint8_t* instr);
void handle_vextractf128(VMContext* ctx, uint8_t* instr);
void handle_vperm2f128(VMContext* ctx, uint8_t* instr);
void handle_vblendvpd(VMContext* ctx, uint8_t* instr);
void handle_vaddps(VMContext* ctx, uint8_t* instr);
void handle_vsubps(VMContext* ctx, uint8_t* instr);
void handle_vmulps(VMContext* ctx, uint8_t* instr);
void handle_vdivps(VMContext* ctx, uint8_t* instr);
void handle_vandps(VMContext* ctx, uint8_t* instr);
void handle_vorps(VMContext* ctx, uint8_t* instr);
void handle_vxorps(VMContext* ctx, uint8_t* instr);
void handle_vblendps(VMContext* ctx, uint8_t* instr);
void handle_vminps(VMContext* ctx, uint8_t* instr);
void handle_vmaxps(VMContext* ctx, uint8_t* instr);

// System and Control Instructions
void handle_cpuid(VMContext* ctx, uint8_t* instr);
void handle_rdtsc(VMContext* ctx, uint8_t* instr);
void handle_cld(VMContext* ctx, uint8_t* instr);
void handle_std(VMContext* ctx, uint8_t* instr);
void handle_cli(VMContext* ctx, uint8_t* instr);
void handle_sti(VMContext* ctx, uint8_t* instr);
void handle_hlt(VMContext* ctx, uint8_t* instr);
void handle_int(VMContext* ctx, uint8_t* instr);
void handle_iret(VMContext* ctx, uint8_t* instr);
void handle_op_in(VMContext* ctx, uint8_t* instr);
void handle_op_out(VMContext* ctx, uint8_t* instr);
void handle_lahf(VMContext* ctx, uint8_t* instr);
void handle_sahf(VMContext* ctx, uint8_t* instr);
void handle_clts(VMContext* ctx, uint8_t* instr);
void handle_lgdt(VMContext* ctx, uint8_t* instr);
void handle_sgdt(VMContext* ctx, uint8_t* instr);
void handle_lidt(VMContext* ctx, uint8_t* instr);
void handle_sidt(VMContext* ctx, uint8_t* instr);
void handle_lmsw(VMContext* ctx, uint8_t* instr);
void handle_smsw(VMContext* ctx, uint8_t* instr);
void handle_rdmsr(VMContext* ctx, uint8_t* instr);
void handle_wrmsr(VMContext* ctx, uint8_t* instr);
void handle_rdpmc(VMContext* ctx, uint8_t* instr);
void handle_rsm(VMContext* ctx, uint8_t* instr);
void handle_ud2(VMContext* ctx, uint8_t* instr);

// MMX Instructions
void handle_emms(VMContext* ctx, uint8_t* instr);
void handle_movd(VMContext* ctx, uint8_t* instr);
void handle_movq(VMContext* ctx, uint8_t* instr);
void handle_packsswb(VMContext* ctx, uint8_t* instr);
void handle_packssdw(VMContext* ctx, uint8_t* instr);
void handle_packuswb(VMContext* ctx, uint8_t* instr);
void handle_mmx_paddq(VMContext* ctx, uint8_t* instr);
void handle_mmx_paddb(VMContext* ctx, uint8_t* instr);
void handle_mmx_paddw(VMContext* ctx, uint8_t* instr);
void handle_mmx_paddd(VMContext* ctx, uint8_t* instr);
void handle_mmx_psubb(VMContext* ctx, uint8_t* instr);
void handle_mmx_psubw(VMContext* ctx, uint8_t* instr);
void handle_mmx_psubd(VMContext* ctx, uint8_t* instr);
void handle_mmx_psubq(VMContext* ctx, uint8_t* instr);
void handle_pmaddwd(VMContext* ctx, uint8_t* instr);
void handle_pmulhw(VMContext* ctx, uint8_t* instr);
void handle_pmullw(VMContext* ctx, uint8_t* instr);
void handle_pavgb(VMContext* ctx, uint8_t* instr);
void handle_pavgw(VMContext* ctx, uint8_t* instr);
void handle_pminub(VMContext* ctx, uint8_t* instr);
void handle_pmaxub(VMContext* ctx, uint8_t* instr);
void handle_pminsw(VMContext* ctx, uint8_t* instr);
void handle_pmaxsw(VMContext* ctx, uint8_t* instr);
void handle_psadbw(VMContext* ctx, uint8_t* instr);
void handle_pshufw(VMContext* ctx, uint8_t* instr);
void handle_maskmovq(VMContext* ctx, uint8_t* instr);
void handle_movntq(VMContext* ctx, uint8_t* instr);
void handle_pandn(VMContext* ctx, uint8_t* instr);
void handle_pcmpgtb(VMContext* ctx, uint8_t* instr);
void handle_pcmpgtw(VMContext* ctx, uint8_t* instr);
void handle_pcmpgtd(VMContext* ctx, uint8_t* instr);
void handle_pextrw(VMContext* ctx, uint8_t* instr);
void handle_pinsrw(VMContext* ctx, uint8_t* instr);
void handle_pmaddubsw(VMContext* ctx, uint8_t* instr);
void handle_pmaxsd(VMContext* ctx, uint8_t* instr);
void handle_pminsd(VMContext* ctx, uint8_t* instr);
void handle_pmuludq(VMContext* ctx, uint8_t* instr);
void handle_pshufb(VMContext* ctx, uint8_t* instr);
void handle_psignb(VMContext* ctx, uint8_t* instr);
void handle_psignw(VMContext* ctx, uint8_t* instr);
void handle_psignd(VMContext* ctx, uint8_t* instr);
void handle_psubusb(VMContext* ctx, uint8_t* instr);
void handle_psubusw(VMContext* ctx, uint8_t* instr);
void handle_psrlw(VMContext* ctx, uint8_t* instr);
void handle_psraw(VMContext* ctx, uint8_t* instr);
void handle_psllw(VMContext* ctx, uint8_t* instr);
void handle_psubsb(VMContext* ctx, uint8_t* instr);
void handle_psubsw(VMContext* ctx, uint8_t* instr);
void handle_punpcklbw(VMContext* ctx, uint8_t* instr);
void handle_punpcklwd(VMContext* ctx, uint8_t* instr);
void handle_punpckldq(VMContext* ctx, uint8_t* instr);
void handle_punpckhbw(VMContext* ctx, uint8_t* instr);
void handle_punpckhwd(VMContext* ctx, uint8_t* instr);
void handle_punpckhdq(VMContext* ctx, uint8_t* instr);
void handle_movd_ext(VMContext* ctx, uint8_t* instr);
void handle_movq_ext(VMContext* ctx, uint8_t* instr);
void handle_pmovmskb(VMContext* ctx, uint8_t* instr);
void handle_pmulhrsw(VMContext* ctx, uint8_t* instr);
void handle_pshuflw(VMContext* ctx, uint8_t* instr);
void handle_pshufhw(VMContext* ctx, uint8_t* instr);
void handle_pslldq(VMContext* ctx, uint8_t* instr);
void handle_psrldq(VMContext* ctx, uint8_t* instr);
void handle_ptest(VMContext* ctx, uint8_t* instr);

// VM Control and Junk
void handle_exit(VMContext* ctx, uint8_t* instr);
void handle_junk(VMContext* ctx, uint8_t* instr);

#endif // LOADER_CORE_H