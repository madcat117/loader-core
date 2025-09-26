//
// loader_core.h
//
// This is the central header file for the entire virtualization and protection engine.
// It defines all core data structures, constants, error codes, VM opcodes,
// and function prototypes used by the protector and the generated loader.
// This version has been massively expanded to be the foundation of a robust system.
//

#ifndef LOADER_CORE_H
#define LOADER_CORE_H

// --- Section 1: System and Standard Library Includes ---
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <array>
#include <map>
#include <immintrin.h> // For AVX/SSE intrinsics
#include <wincrypt.h>
#include <bcrypt.h>
#include <psapi.h>
#include <imagehlp.h>
#include <winternl.h>


// --- Section 2: Core Constants and Preprocessor Definitions ---

// Undefine conflicting Windows macros to prevent compilation errors.
#ifdef ERROR_STACK_OVERFLOW
#undef ERROR_STACK_OVERFLOW
#endif
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#define LOADER_CORE_VERSION "3.0.0-Godlike"

const int NUM_GENERAL_PURPOSE_REGISTERS = 16;
const int NUM_VECTOR_REGISTERS = 16;
const int INITIAL_STACK_SIZE_BYTES = 16384;      // 16 KB stack
const size_t MAX_VIRTUALIZED_CODE_SIZE = 65536; // 64 KB max for VM bytecode
const size_t VM_MEMORY_SPACE_SIZE = 131072;     // 128 KB for general-purpose VM memory
const int FPU_STACK_REGISTER_COUNT = 8;
const uint64_t VM_EXECUTION_TIMEOUT_STEPS = 10000000; // Max steps before timeout
const char* VMP_SECTION_NAME = ".vmptext";
const int AES_KEY_SIZE = 32;
const int GCM_NONCE_SIZE = 12;
const int GCM_TAG_SIZE = 16;

// --- Section 3: Core Data Structures and Enums ---

/**
 * @enum ProtectionError
 * @brief Comprehensive error codes for all potential failures in the system.
 */
enum class ProtectionError : int {
    SUCCESS = 0,
    ERROR_INVALID_OPCODE = -1, ERROR_OUT_OF_BOUNDS = -2, ERROR_STACK_OVERFLOW = -3,
    ERROR_STACK_UNDERFLOW = -4, ERROR_DIVISION_BY_ZERO = -5, ERROR_MOD_BY_ZERO = -6,
    ERROR_INVALID_REGISTER = -7, ERROR_VM_HALT_TIMEOUT = -8, ERROR_INVALID_MEMORY_ACCESS = -9,
    ERROR_FPU_STACK_OVERFLOW = -15, ERROR_FPU_STACK_UNDERFLOW = -16, ERROR_INTEGER_OVERFLOW = -21,
    ERROR_DISASSEMBLY_FAILURE = -47, ERROR_RECOMPILATION_FAILURE = -48, ERROR_BINARY_PATCH_FAILURE = -49,
    ERROR_INSUFFICIENT_MEMORY_RESOURCES = -55, ERROR_CODE_TAMPERING_DETECTED = -57,
    ERROR_CRYPTO_FAILURE = -60, ERROR_LOADER_GENERATION_FAILURE = -61, ERROR_ANTI_DEBUG_DETECTED = -62,
    ERROR_ANTI_VM_DETECTED = -63, ERROR_FILE_IO = -64,
    ERROR_UNKNOWN = -100
};

/**
 * @enum Opcodes
 * @brief The complete instruction set for the custom virtual machine.
 * Total Opcodes: 295 (0x00 to 0x126)
 */
enum class Opcodes : uint16_t {
    NOP = 0x00, ADD, SUB, MUL, DIV, AND, OR, NOT, SHL, SHR, XOR, LOAD, STORE, JMP, JZ, JNZ, JC, JNC, CMP, INC, DEC,
    MOV, LOAD_IMM, PUSH, POP, CALL, RET, IMUL, IDIV, SAR, ROL, ROR, TEST, CMOVE, CMOVNE, LEA, JBE, JA, JS, JNS,
    JO, JNO, JP, JNP, ADC, SBB, JLE, JG, NEG, BSWAP, POPCNT, LZCNT, TZCNT, RCL, RCR, SHLD, SHRD, BT, BTS, BTR, BTC,
    CMOVZ, CMOVNZ, SETZ, SETNZ, SETC, SETNC, SETS, SETNS, SETO, SETNO, SETP, SETNP, SETBE, SETA, SETLE, SETG,
    CMOVBE, CMOVA, CMOVS, CMOVNS, CMOVO, CMOVNO, CMOVP, CMOVNP, CMOVLE, CMOVG, BSF, BSR, MOD, IMOD, ADD32,
    SUB32, MUL32, DIV32, IMUL32, IDIV32, MOD32, IMOD32, FADD, FSUB, FMUL, FDIV, FLD, FST, FCMP, PADDD, PSUBD,
    PMULD, PDIVD, MOVDQA, PCMPEQD, PAND, POR, PXOR, PSLLD, PSRLD, PSLLQ, PSRLQ, MOVDQU, CVTSI2SD, CVTSD2SI,
    SQRTSD, MINSD, MAXSD, ANDPD, ORPD, XORPD, BLENDPD, ROUNDPD, VADDPD, VSUBPD, VMULPD, VDIVPD, VMOVAPD,
    VCMP_PD, VBROADCASTSD, VPERMILPD, VFMSUBADDPD, VMASKMOVPD, VGATHERDPD, VSCATTERDPD, VAESENC, VAESDEC,
    VPCLMULQDQ, VPCMPEQD, VPSHUFD, VINSERTF128, VEXTRACTF128, VPERM2F128, VBLENDVPD, PUSHF, POPF, CPUID,
    RDTSC, XCHG, CLD, STD, CLI, STI, HLT, INT, IRET, LOOP, LOOPE, LOOPNE, OP_IN, OP_OUT, LAHF, SAHF, CLTS,
    LGDT, SGDT, LIDT, SIDT, LMSW, SMSW, RDMSR, WRMSR, RDPMC, RSM, UD2, EMMS, MOVD, MOVQ, PACKSSWB, PACKSSDW,
    PACKUSWB, MMX_PADDQ, MMX_PADDB, MMX_PADDW, MMX_PADDD, MMX_PSUBB, MMX_PSUBW, MMX_PSUBD, MMX_PSUBQ,
    PMADDWD, PMULHW, PMULLW, PAVGB, PAVGW, PMINUB, PMAXUB, PMINSW, PMAXSW, PSADBW, PSHUFW, MASKMOVQ,
    MOVNTQ, PANDN, PCMPGTB, PCMPGTW, PCMPGTD, PEXTRW, PINSRW, PMADDUBSW, PMAXSD, PMINSD, PMULUDQ,
    PSHUFB, PSIGNB, PSIGNW, PSIGND, PSUBUSB, PSUBUSW, PSRLW, PSRAW, PSLLW, PSUBSB, PSUBSW, PUNPCKLBW,
    PUNPCKLWD, PUNPCKLDQ, PUNPCKHBW, PUNPCKHWD, PUNPCKHDQ, MOVD_EXT, MOVQ_EXT, PMOVMSKB, PMULHRSW,
    PSHUFLW, PSHUFHW, PSLLDQ, PSRLDQ, PTEST, VADDPS, VSUBPS, VMULPS, VDIVPS, VANDPS, VORPS, VXORPS,
    VBLENDPS, VMINPS, VMAXPS, EXIT,
    JUNK1 = 0x114, JUNK2, JUNK3, JUNK4, JUNK5, JUNK6, JUNK7, JUNK8, JUNK9, JUNK10,
    JUNK11, JUNK12, JUNK13, JUNK14, JUNK15, JUNK16, JUNK17, JUNK18, JUNK19, JUNK20,
    OPCODE_COUNT // Must be the last real opcode
};

/**
 * @struct ProtectorSettings
 * @brief Defines configurable options for the protection process.
 */
struct ProtectorSettings {
    bool enable_junk_insertion = true;
    bool enable_anti_debugging = true;
    bool enable_anti_vm = true;
    int junk_probability = 15;
};

/**
 * @struct VMFlags
 * @brief State of the virtual CPU's arithmetic and control flags.
 */
struct VMFlags {
    bool zero = false; bool carry = false; bool sign = false;
    bool overflow = false; bool parity = false;
};

/**
 * @struct YMM_REG
 * @brief A union to represent a 256-bit YMM register for AVX, which also provides
 * access to its lower 128-bit XMM part and 64-bit integer parts.
 */
struct alignas(32) YMM_REG {
    union {
        __m256 ymm_float; __m256d ymm_double; __m256i ymm_int;
        __m128 xmm[2]; uint64_t u64[4]; uint32_t u32[8];
        uint16_t u16[16]; uint8_t u8[32];
    };
};

/**
 * @struct VMContext
 * @brief The complete state of the virtual machine.
 */
struct VMContext {
    uint64_t regs[NUM_GENERAL_PURPOSE_REGISTERS];
    YMM_REG ymm_regs[NUM_VECTOR_REGISTERS];
    uint8_t* ip; std::vector<uint8_t> stack; size_t sp; VMFlags flags; bool running;
    ProtectionError last_error; std::vector<uint8_t> memory;
    std::array<double, FPU_STACK_REGISTER_COUNT> fpu_stack; int fpu_top;
    uint64_t code_hash; uint64_t step_count;
};

/**
 * @struct IRInstruction
 * @brief Intermediate Representation for a single assembly instruction.
 */
struct IRInstruction {
    Opcodes opcode;
    std::vector<std::string> operands;
    uint64_t original_address;
    size_t size;
};

// --- Section 4: Public Function Prototypes ---

// Main protection workflow functions
void protect_function(const std::string& dll_path, uint64_t func_rva, const ProtectorSettings& settings);
void generate_loader(const std::string& protected_dll, const std::string& protected_meta, const ProtectorSettings& settings);
bool encrypt_file(const std::string& input_path, const std::string& output_path);
std::string to_hex_string(uint64_t val);

// VM core functions
void InitVM(VMContext& ctx, uint8_t* virtualized_code, size_t code_size);
void run_vm(VMContext* ctx, uint64_t max_steps = VM_EXECUTION_TIMEOUT_STEPS);

// Disassembly and Recompilation
std::vector<IRInstruction> lift_to_ir(const std::vector<uint8_t>& code, uint64_t base_addr);
std::vector<uint8_t> recompile_to_vm(const std::vector<IRInstruction>& ir, const ProtectorSettings& settings);

// PE File Manipulation
bool AddSectionToPe(const std::string& file_path, const char* section_name, DWORD size_of_section, const std::vector<uint8_t>& section_data);
bool PatchFile(const std::string& file_path, uint64_t rva, const std::vector<uint8_t>& patch_data);
std::vector<uint8_t> ReadFileBytes(const std::string& path);
bool WriteFileBytes(const std::string& path, const std::vector<uint8_t>& data);

// --- Section 5: VM Opcode Handler Prototypes ---
using Handler = void (*)(VMContext* ctx);
extern Handler g_handlers[static_cast<size_t>(Opcodes::OPCODE_COUNT)];
void bind_handlers();

#define DECLARE_HANDLER(name) void handle_##name(VMContext* ctx)

DECLARE_HANDLER(nop); DECLARE_HANDLER(add); DECLARE_HANDLER(sub); DECLARE_HANDLER(mul); DECLARE_HANDLER(div);
DECLARE_HANDLER(and); DECLARE_HANDLER(or); DECLARE_HANDLER(not); DECLARE_HANDLER(shl); DECLARE_HANDLER(shr);
DECLARE_HANDLER(xor); DECLARE_HANDLER(load); DECLARE_HANDLER(store); DECLARE_HANDLER(jmp); DECLARE_HANDLER(jz);
DECLARE_HANDLER(jnz); DECLARE_HANDLER(jc); DECLARE_HANDLER(jnc); DECLARE_HANDLER(cmp); DECLARE_HANDLER(inc);
DECLARE_HANDLER(dec); DECLARE_HANDLER(mov); DECLARE_HANDLER(load_imm); DECLARE_HANDLER(push); DECLARE_HANDLER(pop);
DECLARE_HANDLER(call); DECLARE_HANDLER(ret); DECLARE_HANDLER(imul); DECLARE_HANDLER(idiv); DECLARE_HANDLER(sar);
DECLARE_HANDLER(rol); DECLARE_HANDLER(ror); DECLARE_HANDLER(test); DECLARE_HANDLER(cmove); DECLARE_HANDLER(cmovne);
DECLARE_HANDLER(lea); DECLARE_HANDLER(jbe); DECLARE_HANDLER(ja); DECLARE_HANDLER(js); DECLARE_HANDLER(jns);
DECLARE_HANDLER(jo); DECLARE_HANDLER(jno); DECLARE_HANDLER(jp); DECLARE_HANDLER(jnp); DECLARE_HANDLER(adc);
DECLARE_HANDLER(sbb); DECLARE_HANDLER(jle); DECLARE_HANDLER(jg); DECLARE_HANDLER(neg); DECLARE_HANDLER(bswap);
DECLARE_HANDLER(popcnt); DECLARE_HANDLER(lzcnt); DECLARE_HANDLER(tzcnt); DECLARE_HANDLER(rcl); DECLARE_HANDLER(rcr);
DECLARE_HANDLER(shld); DECLARE_HANDLER(shrd); DECLARE_HANDLER(bt); DECLARE_HANDLER(bts); DECLARE_HANDLER(btr);
DECLARE_HANDLER(btc); DECLARE_HANDLER(cmovz); DECLARE_HANDLER(cmovnz); DECLARE_HANDLER(setz); DECLARE_HANDLER(setnz);
DECLARE_HANDLER(setc); DECLARE_HANDLER(setnc); DECLARE_HANDLER(sets); DECLARE_HANDLER(setns); DECLARE_HANDLER(seto);
DECLARE_HANDLER(setno); DECLARE_HANDLER(setp); DECLARE_HANDLER(setnp); DECLARE_HANDLER(setbe); DECLARE_HANDLER(seta);
DECLARE_HANDLER(setle); DECLARE_HANDLER(setg); DECLARE_HANDLER(cmovbe); DECLARE_HANDLER(cmova); DECLARE_HANDLER(cmovs);
DECLARE_HANDLER(cmovns); DECLARE_HANDLER(cmovo); DECLARE_HANDLER(cmovno); DECLARE_HANDLER(cmovp); DECLARE_HANDLER(cmovnp);
DECLARE_HANDLER(cmovle); DECLARE_HANDLER(cmovg); DECLARE_HANDLER(bsf); DECLARE_HANDLER(bsr); DECLARE_HANDLER(mod);
DECLARE_HANDLER(imod); DECLARE_HANDLER(add32); DECLARE_HANDLER(sub32); DECLARE_HANDLER(mul32); DECLARE_HANDLER(div32);
DECLARE_HANDLER(imul32); DECLARE_HANDLER(idiv32); DECLARE_HANDLER(mod32); DECLARE_HANDLER(imod32); DECLARE_HANDLER(fadd);
DECLARE_HANDLER(fsub); DECLARE_HANDLER(fmul); DECLARE_HANDLER(fdiv); DECLARE_HANDLER(fld); DECLARE_HANDLER(fst);
DECLARE_HANDLER(fcmp); DECLARE_HANDLER(paddd); DECLARE_HANDLER(psubd); DECLARE_HANDLER(pmuld); DECLARE_HANDLER(pdivd);
DECLARE_HANDLER(movdqa); DECLARE_HANDLER(pcmpeqd); DECLARE_HANDLER(pand); DECLARE_HANDLER(por); DECLARE_HANDLER(pxor);
DECLARE_HANDLER(pslld); DECLARE_HANDLER(psrld); DECLARE_HANDLER(psllq); DECLARE_HANDLER(psrlq); DECLARE_HANDLER(movdqu);
DECLARE_HANDLER(cvtsi2sd); DECLARE_HANDLER(cvtsd2si); DECLARE_HANDLER(sqrtsd); DECLARE_HANDLER(minsd); DECLARE_HANDLER(maxsd);
DECLARE_HANDLER(andpd); DECLARE_HANDLER(orpd); DECLARE_HANDLER(xorpd); DECLARE_HANDLER(blendpd); DECLARE_HANDLER(roundpd);
DECLARE_HANDLER(vaddpd); DECLARE_HANDLER(vsubpd); DECLARE_HANDLER(vmulpd); DECLARE_HANDLER(vdivpd); DECLARE_HANDLER(vmovapd);
DECLARE_HANDLER(vcmp_pd); DECLARE_HANDLER(vbroadcastsd); DECLARE_HANDLER(vpermilpd); DECLARE_HANDLER(vfmsubaddpd);
DECLARE_HANDLER(vmaskmovpd); DECLARE_HANDLER(vgatherdpd); DECLARE_HANDLER(vscatterdpd); DECLARE_HANDLER(vaesenc);
DECLARE_HANDLER(vaesdec); DECLARE_HANDLER(vpclmulqdq); DECLARE_HANDLER(vpcmpeqd); DECLARE_HANDLER(vpshufd);
DECLARE_HANDLER(vinsertf128); DECLARE_HANDLER(vextractf128); DECLARE_HANDLER(vperm2f128); DECLARE_HANDLER(vblendvpd);
DECLARE_HANDLER(pushf); DECLARE_HANDLER(popf); DECLARE_HANDLER(cpuid); DECLARE_HANDLER(rdtsc); DECLARE_HANDLER(xchg);
DECLARE_HANDLER(cld); DECLARE_HANDLER(std); DECLARE_HANDLER(cli); DECLARE_HANDLER(sti); DECLARE_HANDLER(hlt);
DECLARE_HANDLER(int); DECLARE_HANDLER(iret); DECLARE_HANDLER(loop); DECLARE_HANDLER(loope); DECLARE_HANDLER(loopne);
DECLARE_HANDLER(op_in); DECLARE_HANDLER(op_out); DECLARE_HANDLER(lahf); DECLARE_HANDLER(sahf); DECLARE_HANDLER(clts);
DECLARE_HANDLER(lgdt); DECLARE_HANDLER(sgdt); DECLARE_HANDLER(lidt); DECLARE_HANDLER(sidt); DECLARE_HANDLER(lmsw);
DECLARE_HANDLER(smsw); DECLARE_HANDLER(rdmsr); DECLARE_HANDLER(wrmsr); DECLARE_HANDLER(rdpmc); DECLARE_HANDLER(rsm);
DECLARE_HANDLER(ud2); DECLARE_HANDLER(emms); DECLARE_HANDLER(movd); DECLARE_HANDLER(movq); DECLARE_HANDLER(packsswb);
DECLARE_HANDLER(packssdw); DECLARE_HANDLER(packuswb); DECLARE_HANDLER(mmx_paddq); DECLARE_HANDLER(mmx_paddb);
DECLARE_HANDLER(mmx_paddw); DECLARE_HANDLER(mmx_paddd); DECLARE_HANDLER(mmx_psubb); DECLARE_HANDLER(mmx_psubw);
DECLARE_HANDLER(mmx_psubd); DECLARE_HANDLER(mmx_psubq); DECLARE_HANDLER(pmaddwd); DECLARE_HANDLER(pmulhw);
DECLARE_HANDLER(pmullw); DECLARE_HANDLER(pavgb); DECLARE_HANDLER(pavgw); DECLARE_HANDLER(pminub); DECLARE_HANDLER(pmaxub);
DECLARE_HANDLER(pminsw); DECLARE_HANDLER(pmaxsw); DECLARE_HANDLER(psadbw); DECLARE_HANDLER(pshufw);
DECLARE_HANDLER(maskmovq); DECLARE_HANDLER(movntq); DECLARE_HANDLER(pandn); DECLARE_HANDLER(pcmpgtb);
DECLARE_HANDLER(pcmpgtw); DECLARE_HANDLER(pcmpgtd); DECLARE_HANDLER(pextrw); DECLARE_HANDLER(pinsrw);
DECLARE_HANDLER(pmaddubsw); DECLARE_HANDLER(pmaxsd); DECLARE_HANDLER(pminsd); DECLARE_HANDLER(pmuludq);
DECLARE_HANDLER(pshufb); DECLARE_HANDLER(psignb); DECLARE_HANDLER(psignw); DECLARE_HANDLER(psignd);
DECLARE_HANDLER(psubusb); DECLARE_HANDLER(psubusw); DECLARE_HANDLER(psrlw); DECLARE_HANDLER(psraw);
DECLARE_HANDLER(psllw); DECLARE_HANDLER(psubsb); DECLARE_HANDLER(psubsw); DECLARE_HANDLER(punpcklbw);
DECLARE_HANDLER(punpcklwd); DECLARE_HANDLER(punpckldq); DECLARE_HANDLER(punpckhbw); DECLARE_HANDLER(punpckhwd);
DECLARE_HANDLER(punpckhdq); DECLARE_HANDLER(movd_ext); DECLARE_HANDLER(movq_ext); DECLARE_HANDLER(pmovmskb);
DECLARE_HANDLER(pmulhrsw); DECLARE_HANDLER(pshuflw); DECLARE_HANDLER(pshufhw); DECLARE_HANDLER(pslldq);
DECLARE_HANDLER(psrldq); DECLARE_HANDLER(ptest); DECLARE_HANDLER(vaddps); DECLARE_HANDLER(vsubps);
DECLARE_HANDLER(vmulps); DECLARE_HANDLER(vdivps); DECLARE_HANDLER(vandps); DECLARE_HANDLER(vorps);
DECLARE_HANDLER(vxorps); DECLARE_HANDLER(vblendps); DECLARE_HANDLER(vminps); DECLARE_HANDLER(vmaxps);
DECLARE_HANDLER(exit); DECLARE_HANDLER(junk);

#endif // LOADER_CORE_H