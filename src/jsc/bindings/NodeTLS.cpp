#include "config.h"

#include "JavaScriptCore/JSObject.h"
#include "JavaScriptCore/ObjectConstructor.h"
#include "JavaScriptCore/ArrayConstructor.h"
#include "libusockets.h"

#include "ZigGlobalObject.h"
#include "ErrorCode.h"
#include "openssl/base.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
#include "openssl/sha.h"
#include "openssl/err.h"
#include <limits.h>
#include "JavaScriptCore/JSArrayBufferView.h"
#include "../../packages/bun-usockets/src/crypto/root_certs_header.h"

namespace Bun {

using namespace JSC;

JSC_DEFINE_HOST_FUNCTION(getBundledRootCertificates, (JSC::JSGlobalObject * globalObject, JSC::CallFrame* callFrame))
{
    VM& vm = globalObject->vm();

    struct us_cert_string_t* out;
    auto size = us_raw_root_certs(&out);
    if (size < 0) {
        return JSValue::encode(jsUndefined());
    }
    auto rootCertificates = JSC::JSArray::create(vm, globalObject->arrayStructureForIndexingTypeDuringAllocation(JSC::ArrayWithContiguous), size);
    for (auto i = 0; i < size; i++) {
        auto raw = out[i];
        auto str = WTF::String::fromUTF8(std::span { raw.str, raw.len });
        rootCertificates->putDirectIndex(globalObject, i, JSC::jsString(vm, str));
    }

    return JSValue::encode(JSC::objectConstructorFreeze(globalObject, rootCertificates));
}

JSC_DEFINE_HOST_FUNCTION(getExtraCACertificates, (JSC::JSGlobalObject * globalObject, JSC::CallFrame* callFrame))
{
    auto scope = DECLARE_THROW_SCOPE(globalObject->vm());
    VM& vm = globalObject->vm();

    STACK_OF(X509)* root_extra_cert_instances = us_get_root_extra_cert_instances();

    auto size = sk_X509_num(root_extra_cert_instances);
    if (size < 0) size = 0; // root_extra_cert_instances is nullptr

    JSC::MarkedArgumentBuffer args;
    for (auto i = 0; i < size; i++) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throwOutOfMemoryError(globalObject, scope);
            return {};
        }

        if (PEM_write_bio_X509(bio, sk_X509_value(root_extra_cert_instances, i)) != 1) {
            BIO_free(bio);
            return throwError(globalObject, scope, ErrorCode::ERR_CRYPTO_OPERATION_FAILED, "X509 to PEM conversion"_str);
        }

        char* bioData = nullptr;
        long bioLen = BIO_get_mem_data(bio, &bioData);
        if (bioLen <= 0 || !bioData) {
            BIO_free(bio);
            return throwError(globalObject, scope, ErrorCode::ERR_CRYPTO_OPERATION_FAILED, "Reading PEM data"_str);
        }

        auto str = WTF::String::fromUTF8(std::span { bioData, static_cast<size_t>(bioLen) });
        args.append(JSC::jsString(vm, str));
        BIO_free(bio);
    }

    if (args.hasOverflowed()) {
        throwOutOfMemoryError(globalObject, scope);
        return {};
    }

    auto rootCertificates = JSC::constructArray(globalObject, static_cast<JSC::ArrayAllocationProfile*>(nullptr), args);
    RETURN_IF_EXCEPTION(scope, {});

    RELEASE_AND_RETURN(scope, JSValue::encode(JSC::objectConstructorFreeze(globalObject, rootCertificates)));
}

JSC_DEFINE_HOST_FUNCTION(getSystemCACertificates, (JSC::JSGlobalObject * globalObject, JSC::CallFrame* callFrame))
{
    auto scope = DECLARE_THROW_SCOPE(globalObject->vm());
    VM& vm = globalObject->vm();

    STACK_OF(X509)* root_system_cert_instances = us_get_root_system_cert_instances();

    auto size = sk_X509_num(root_system_cert_instances);
    if (size < 0) size = 0; // root_system_cert_instances is nullptr

    JSC::MarkedArgumentBuffer args;
    for (auto i = 0; i < size; i++) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throwOutOfMemoryError(globalObject, scope);
            return {};
        }
        X509* cert = sk_X509_value(root_system_cert_instances, i);
        if (!cert) {
            BIO_free(bio);
            continue;
        }
        if (!PEM_write_bio_X509(bio, cert)) {
            BIO_free(bio);
            continue;
        }

        char* bioData;
        long bioLen = BIO_get_mem_data(bio, &bioData);
        if (bioLen <= 0) {
            BIO_free(bio);
            continue;
        }

        auto str = WTF::String::fromUTF8(std::span { bioData, static_cast<size_t>(bioLen) });
        args.append(JSC::jsString(vm, str));
        BIO_free(bio);
    }

    if (args.hasOverflowed()) {
        throwOutOfMemoryError(globalObject, scope);
        return {};
    }

    auto rootCertificates = JSC::constructArray(globalObject, static_cast<JSC::ArrayAllocationProfile*>(nullptr), args);
    RETURN_IF_EXCEPTION(scope, {});

    RELEASE_AND_RETURN(scope, JSValue::encode(JSC::objectConstructorFreeze(globalObject, rootCertificates)));
}

extern "C" JSC::EncodedJSValue Bun__getTLSDefaultCiphers(JSC::JSGlobalObject* globalObject, JSC::CallFrame* callFrame);
extern "C" JSC::EncodedJSValue Bun__setTLSDefaultCiphers(JSC::JSGlobalObject* globalObject, JSC::CallFrame* callFrame);

JSC_DEFINE_HOST_FUNCTION(getDefaultCiphers, (JSC::JSGlobalObject * globalObject, JSC::CallFrame* callFrame))
{
    return Bun__getTLSDefaultCiphers(globalObject, callFrame);
}

JSC_DEFINE_HOST_FUNCTION(setDefaultCiphers, (JSC::JSGlobalObject * globalObject, JSC::CallFrame* callFrame))
{
    return Bun__setTLSDefaultCiphers(globalObject, callFrame);
}

JSC_DEFINE_HOST_FUNCTION(addBlockedSPKIForTesting, (JSC::JSGlobalObject* globalObject, JSC::CallFrame* callFrame))
{
    auto& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);
    auto* hash = dynamicDowncast<JSC::JSArrayBufferView>(callFrame->argument(0));
    if (!hash) return ERR::INVALID_ARG_TYPE(scope, globalObject, "SPKI hash must be a buffer"_s);
    if (hash->byteLength() != SHA256_DIGEST_LENGTH) return ERR::OUT_OF_RANGE(scope, globalObject, "SPKI hash must be 32 bytes"_s);
    us_add_blocked_spki_for_testing(static_cast<const uint8_t*>(hash->vector()));
    return JSValue::encode(jsUndefined());
}

JSC_DEFINE_HOST_FUNCTION(clearBlockedSPKIsForTesting, (JSC::JSGlobalObject* globalObject, JSC::CallFrame* callFrame))
{
    us_clear_blocked_spkis_for_testing();
    return JSValue::encode(jsUndefined());
}

JSC_DEFINE_HOST_FUNCTION(addBlockedCertificateForTesting, (JSC::JSGlobalObject* globalObject, JSC::CallFrame* callFrame))
{
    auto& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);
    auto* hash = dynamicDowncast<JSC::JSArrayBufferView>(callFrame->argument(0));
    if (!hash) return ERR::INVALID_ARG_TYPE(scope, globalObject, "certificate hash must be a buffer"_s);
    if (hash->byteLength() != SHA256_DIGEST_LENGTH) return ERR::OUT_OF_RANGE(scope, globalObject, "certificate hash must be 32 bytes"_s);
    us_add_blocked_certificate_for_testing(static_cast<const uint8_t*>(hash->vector()));
    return JSValue::encode(jsUndefined());
}

JSC_DEFINE_HOST_FUNCTION(clearBlockedCertificatesForTesting, (JSC::JSGlobalObject* globalObject, JSC::CallFrame* callFrame))
{
    us_clear_blocked_certificates_for_testing();
    return JSValue::encode(jsUndefined());
}

// Inspect a public certificate against the compiled denylist without a private
// key, handshake, or any change to the production entries.
JSC_DEFINE_HOST_FUNCTION(certificateBlockedErrorForTesting, (JSC::JSGlobalObject* globalObject, JSC::CallFrame* callFrame))
{
    auto& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);
    auto value = callFrame->argument(0);
    if (!value.isString()) return ERR::INVALID_ARG_TYPE(scope, globalObject, "certificate must be a PEM string"_s);
    auto pem = value.toWTFString(globalObject);
    RETURN_IF_EXCEPTION(scope, {});
    auto bytes = pem.utf8();
    if (bytes.length() > INT_MAX) return ERR::OUT_OF_RANGE(scope, globalObject, "certificate is too large"_s);
    BIO* bio = BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.length()));
    if (!bio) {
        throwOutOfMemoryError(globalObject, scope);
        return {};
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) {
        ERR_clear_error();
        return JSValue::encode(jsNumber(X509_V_ERR_UNSPECIFIED));
    }
    int error = us_x509_certificate_blocked_error(cert);
    X509_free(cert);
    return JSValue::encode(jsNumber(error));
}

} // namespace Bun
