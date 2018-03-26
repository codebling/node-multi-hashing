#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
	#include "fresh.h"
}

#include "boolberry.h"

namespace multihashing {
using namespace node;
using namespace Nan;
using namespace v8;

void except(const char* msg) {
    return Nan::ThrowError(msg);
}

NAN_METHOD(quark) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    quark_hash(input, output, input_len);


    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(x11) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    x11_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(scrypt) {
   if (info.Length() < 3)
       return except("You must provide buffer to hash, N value, and R value");

   Local<Object> target = info[0]->ToObject();

   if(!node::Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");

   Local<Number> numn = info[1]->ToNumber();
   unsigned int nValue = numn->Value();
   Local<Number> numr = info[2]->ToNumber();
   unsigned int rValue = numr->Value();

   char * input = node::Buffer::Data(target);
   Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
   char* output = node::Buffer::Data(dest.ToLocalChecked());

   uint32_t input_len = node::Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   info.GetReturnValue().Set(dest.ToLocalChecked());
}



NAN_METHOD(scryptn) {
   if (info.Length() < 2)
       return except("You must provide buffer to hash and N factor.");

   Local<Object> target = info[0]->ToObject();

   if(!node::Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");

   Local<Number> num = info[1]->ToNumber();
   unsigned int nFactor = num->Value();

   char * input = node::Buffer::Data(target);
   Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
   char* output = node::Buffer::Data(dest.ToLocalChecked());

   uint32_t input_len = node::Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now

   info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(scryptjane) {
    if (info.Length() < 5)
        return except("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("First should be a buffer object.");

    Local<Number> num = info[1]->ToNumber();
    int timestamp = num->Value();

    Local<Number> num2 = info[2]->ToNumber();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = info[3]->ToNumber();
    int nMin = num3->Value();

    Local<Number> num4 = info[4]->ToNumber();
    int nMax = num4->Value();

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
   char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(keccak) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    unsigned int dSize = node::Buffer::Length(target);

    keccak_hash(input, output, dSize);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}


NAN_METHOD(bcrypt) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    bcrypt_hash(input, output);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(skein) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    skein_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}


NAN_METHOD(groestl) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    groestl_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}


NAN_METHOD(groestlmyriad) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}


NAN_METHOD(blake) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    blake_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}


NAN_METHOD(fugue) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    fugue_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}


NAN_METHOD(qubit) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    qubit_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}


NAN_METHOD(hefty1) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    hefty1_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}


NAN_METHOD(shavite3) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    shavite3_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(cryptonight) {
    bool fast = false;
    uint32_t cn_variant = 0;

    if (info.Length() < 1)
        return except("You must provide one argument.");

    if (info.Length() >= 2) {
        if (info.Length() >= 2) {
            if(info[1]->IsBoolean())
                fast = info[1]->ToBoolean()->BooleanValue();
            else if(info[1]->IsUint32())
                cn_variant = info[1]->ToUint32()->Uint32Value();
            else
                return except("Argument 2 should be a boolean or uint32_t");
        }
    }

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            return except("Argument must be 43 bytes for monero variant 1+");
        cryptonight_hash(input, output, input_len, cn_variant, 0);
    }

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(cryptonightlite) {
    bool fast = false;
    uint32_t cn_variant = 0;

    if (info.Length() < 1)
        return except("You must provide one argument.");

    if (info.Length() >= 2) {
        if (info.Length() >= 2) {
            if(info[1]->IsBoolean())
                fast = info[1]->ToBoolean()->BooleanValue();
            else if(info[1]->IsUint32())
                cn_variant = info[1]->ToUint32()->Uint32Value();
            else
                return except("Argument 2 should be a boolean or uint32_t");
        }
    }

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            return except("Argument must be 43 bytes for aeon variant 1+");
        cryptonight_hash(input, output, input_len, cn_variant, 1);
    }

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(x13) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    x13_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(boolberry) {
    if (info.Length() < 2)
        return except("You must provide two arguments.");

    Local<Object> target = info[0]->ToObject();
    Local<Object> target_spad = info[1]->ToObject();
    uint32_t height = 1;

    if(!node::Buffer::HasInstance(target))
        return except("Argument 1 should be a buffer object.");

    if(!node::Buffer::HasInstance(target_spad))
        return except("Argument 2 should be a buffer object.");

    if(info.Length() >= 3)
        if(info[2]->IsUint32())
            height = info[2]->ToUint32()->Uint32Value();
        else
            return except("Argument 3 should be an unsigned integer.");

    char * input = node::Buffer::Data(target);
    char * scratchpad = node::Buffer::Data(target_spad);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);
    uint64_t spad_len = node::Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(nist5) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    nist5_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(sha1) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    sha1_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(x15) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    x15_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_METHOD(fresh) {
    if (info.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!node::Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = node::Buffer::Data(target);
    Nan::MaybeLocal<v8::Object> dest = Nan::NewBuffer(32);
    char* output = node::Buffer::Data(dest.ToLocalChecked());

    uint32_t input_len = node::Buffer::Length(target);

    fresh_hash(input, output, input_len);

    info.GetReturnValue().Set(dest.ToLocalChecked());
}

NAN_MODULE_INIT(Init) {
    Nan::Set(target, New<String>("quark").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(quark)).ToLocalChecked());
    Nan::Set(target, New<String>("x11").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(x11)).ToLocalChecked());
    Nan::Set(target, New<String>("scrypt").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(scrypt)).ToLocalChecked());
    Nan::Set(target, New<String>("scryptn").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(scryptn)).ToLocalChecked());
    Nan::Set(target, New<String>("scryptjane").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(scryptjane)).ToLocalChecked());
    Nan::Set(target, New<String>("keccak").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(keccak)).ToLocalChecked());
    Nan::Set(target, New<String>("bcrypt").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(bcrypt)).ToLocalChecked());
    Nan::Set(target, New<String>("skein").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(skein)).ToLocalChecked());
    Nan::Set(target, New<String>("groestl").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(groestl)).ToLocalChecked());
    Nan::Set(target, New<String>("groestlmyriad").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(groestlmyriad)).ToLocalChecked());
    Nan::Set(target, New<String>("blake").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(blake)).ToLocalChecked());
    Nan::Set(target, New<String>("fugue").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(fugue)).ToLocalChecked());
    Nan::Set(target, New<String>("qubit").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(qubit)).ToLocalChecked());
    Nan::Set(target, New<String>("hefty1").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(hefty1)).ToLocalChecked());
    Nan::Set(target, New<String>("shavite3").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(shavite3)).ToLocalChecked());
    Nan::Set(target, New<String>("cryptonight").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, New<String>("cryptonight-lite").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(cryptonightlite)).ToLocalChecked());
    Nan::Set(target, New<String>("x13").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(x13)).ToLocalChecked());
    Nan::Set(target, New<String>("boolberry").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(boolberry)).ToLocalChecked());
    Nan::Set(target, New<String>("nist5").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(nist5)).ToLocalChecked());
    Nan::Set(target, New<String>("sha1").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(sha1)).ToLocalChecked());
    Nan::Set(target, New<String>("x15").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(x15)).ToLocalChecked());
    Nan::Set(target, New<String>("fresh").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(fresh)).ToLocalChecked());
}

NODE_MODULE(multihashing, Init)
}
