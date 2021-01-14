#ifndef CRYPTONIGHT_MULTIHASHING
#define CRYPTONIGHT_MULTIHASHING



void init_ctx ();
void cn_slow_hash_multihash (const void *data, size_t length, void *hash, int variant, int height);
inline void cn_slow_hash_multi (const void *data, size_t length, Crypto::Hash &hash, int variant, int height){
    cn_slow_hash_multihash(data, length, reinterpret_cast<void *>(&hash), variant, height);
}

#endif

/*
void callback(char* data, void* hint); {
    free(data);
}


NAN_METHOD(cryptonight) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;
    bool height_set = false;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<uint32_t>(info[2]).FromMaybe(0);
        height_set = true;
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_0>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 3:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XTL>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 4:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_MSR>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 6:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XAO>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 7:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RTO>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;

       case 8:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_INTEL> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_RYZEN> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_2>         (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
                break;

       case 9:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_HALF>             (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
		break;
       case 11: cryptonight_single_hash_gpu<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_GPU>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 12:
                if (!height_set) return THROW_ERROR_EXCEPTION("CryptonightR requires block template height as Argument 3");

#if !SOFT_AES && (defined(CPU_INTEL) || defined(CPU_AMD))
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_WOW, xmrig::ASM_AUTO>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_WOW>         (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
                break;
       case 13:
                if (!height_set) return THROW_ERROR_EXCEPTION("Cryptonight4 requires block template height as Argument 3");

#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_INTEL> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_RYZEN> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_4>         (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
                break;

       case 14:
                cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RWZ>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;

       case 15:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_ZLS>             (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
		break;

       case 16:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_DOUBLE>             (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
		break;

       default: cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_light) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_0>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       default: cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_heavy) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_XHV >(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 2:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_TUBE>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       default: cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_pico) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:
#if !SOFT_AES && defined(CPU_INTEL)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT_PICO, SOFT_AES, xmrig::VARIANT_TRTL>             (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#endif
                break;
       default:
#if !SOFT_AES && defined(CPU_INTEL)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT_PICO, SOFT_AES, xmrig::VARIANT_TRTL>             (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#endif
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CCryptonightAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        const uint64_t m_height;
        char m_output[32];
        MemInfo m_info;

    public:

        CCryptonightAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant, const uint64_t height)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant), m_height(height) {
            m_info = Mem::create(&m_ctx, xmrig::CRYPTONIGHT, 1);
        }

        ~CCryptonightAsync() {
            Mem::release(&m_ctx, 1, m_info);
        }

        void Execute () {
            switch (m_variant) {
                case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_0>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 3:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XTL>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 4:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_MSR>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 6:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XAO>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 7:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RTO>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;

                case 8:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_2>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                case 9:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_HALF>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                case 11: cryptonight_single_hash_gpu<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_GPU>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;

                case 12:
#if !SOFT_AES && (defined(CPU_INTEL) || defined(CPU_AMD))
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_WOW, xmrig::ASM_AUTO>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_WOW>         (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                case 13:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_4>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                case 14: cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RWZ>               (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;

                case 15:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_ZLS>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                case 16:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_DOUBLE>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                default: cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;

    int callback_arg_num = 1;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    }
    if (info.Length() >= 4) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
        callback_arg_num = 3;
    }

    if ((variant == xmrig::VARIANT_WOW || variant == xmrig::VARIANT_4) && (callback_arg_num < 3)) {
        return THROW_ERROR_EXCEPTION("CryptonightR requires block template height as Argument 3");
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightAsync(callback, Buffer::Data(target), Buffer::Length(target), variant, height));
}

class CCryptonightLightAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        const uint64_t m_height;
        char m_output[32];

    public:

        CCryptonightLightAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant, const uint64_t height)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant), m_height(height) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_LITE_MEMORY, 4096));
        }

        ~CCryptonightLightAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            switch (m_variant) {
                case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_0>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                default: cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_light_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;

    int callback_arg_num = 1;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    }
    if (info.Length() >= 4) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        variant = Nan::To<unsigned int>(info[2]).FromMaybe(0);
        callback_arg_num = 3;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightLightAsync(callback, Buffer::Data(target), Buffer::Length(target), variant, height));
}

class CCryptonightHeavyAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        const uint64_t m_height;
        char m_output[32];

    public:

        CCryptonightHeavyAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant, const uint64_t height)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant), m_height(height) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_HEAVY_MEMORY, 4096));
        }

        ~CCryptonightHeavyAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            switch (m_variant) {
                case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_XHV >(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 2:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_TUBE>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                default: cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_heavy_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;

    int callback_arg_num = 1;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    }
    if (info.Length() >= 4) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        variant = Nan::To<unsigned int>(info[2]).FromMaybe(0);
        callback_arg_num = 3;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightHeavyAsync(callback, Buffer::Data(target), Buffer::Length(target), variant, height));
}


class CCryptonightPicoAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        char m_output[32];

    public:

        CCryptonightPicoAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_PICO_MEMORY, 4096));
        }

        ~CCryptonightPicoAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            switch (m_variant) {
                case 0:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT_PICO, SOFT_AES, xmrig::VARIANT_TRTL>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#endif
			 break;
                default:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT_PICO, SOFT_AES, xmrig::VARIANT_TRTL>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#endif
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_pico_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;

    int callback_arg_num;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    } else {
        callback_arg_num = 1;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightPicoAsync(callback, Buffer::Data(target), Buffer::Length(target), variant));
}

*/
