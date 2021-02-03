#include <stdio.h>
#include <stdint.h>
#ifndef _MSC_VER
#include <sys/mman.h>
#endif

//#if (defined(__AES__) && (__AES__ == 1)) || defined(__APPLE__) || defined(__ARM_ARCH)
//#else
//#define _mm_aeskeygenassist_si128(a, b) a
//#define _mm_aesenc_si128(a, b) a
//#endif

#if defined(__ARM_ARCH)
#include "xmrig/crypto/CryptoNight_arm.h"
#else
#include "xmrig/extra.h"
#include "xmrig/crypto/CryptoNight_x86.h"
#endif

#include "xmrig/Mem.h"
//#include "CryptoTypes.h"
#include "../crypto/types.hpp"

#if (defined(__AES__) && (__AES__ == 1)) || (defined(__ARM_FEATURE_CRYPTO) && (__ARM_FEATURE_CRYPTO == 1))
#define SOFT_AES false
#else
#warning Using software AES
#define SOFT_AES true
#endif

static struct cryptonight_ctx* ctx = NULL;

void init_ctx() {
    if (ctx) return;
    Mem::create(&ctx, xmrig::CRYPTONIGHT_HEAVY, 1);
}


void cn_slow_hash_multihash (const void *data, size_t length, void *hash, int variant, int height)
{
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_0>  (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
       case 3:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XTL>(reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
       case 4:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_MSR>(reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
       case 6:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XAO>(reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
       case 7:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RTO>(reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
        case 8:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_INTEL> (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_RYZEN> (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_2>         (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#endif
                break;

       case 9:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_HALF>             (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#endif
		break;
       case 11: cryptonight_single_hash_gpu<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_GPU>(reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
       case 12:
                //if (!height_set) return THROW_ERROR_EXCEPTION("CryptonightR requires block template height as Argument 3");
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_WOW>         (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
       case 13:
                // if (!height_set) return THROW_ERROR_EXCEPTION("Cryptonight4 requires block template height as Argument 3");

#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_INTEL> (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_RYZEN> (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_4>         (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#endif
                break;

       case 14:
                cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RWZ>(reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;

       case 15:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_ZLS>             (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#endif
		break;

       case 16:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_DOUBLE>             (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#endif
		break;


        ///////////////////////////////////////////////////////
        /// CRYPTONIGHT LITE
        ///////////////////////////////////////////////////////
        case 20:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_0>  (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
        case 21:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;


        ///////////////////////////////////////////////////////
        /// CRYPTONIGHT HEAVY
        ///////////////////////////////////////////////////////
        case 30:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0>  (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
        case 31:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_XHV>  (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
        case 32:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_TUBE>  (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
                break;
        

        ///////////////////////////////////////////////////////
        /// CRYPTONIGHT PICO
        ///////////////////////////////////////////////////////
        case 40:  
#if !SOFT_AES && defined(CPU_INTEL)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT_PICO, SOFT_AES, xmrig::VARIANT_TRTL>             (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
#endif
                break;
        

        default:   
            cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_0>  (reinterpret_cast<const uint8_t*>(data), length, reinterpret_cast<uint8_t*>(hash), &ctx, height);
    }
}

