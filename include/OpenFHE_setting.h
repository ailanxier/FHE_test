#pragma once

#include <openfhe.h>
#include <cryptocontext-ser.h>
#include <key/key-ser.h>
#include "scheme/ckksrns/ckksrns-ser.h"
#include <ciphertext-ser.h>
using namespace lbcrypto;

// ==================== test for CKKS ====================

// Some simple wrapper for OpenFHE Serialize() and Deserialize()
template <typename T>
inline void SerializeToStream(std::fstream& file, const T& obj, const SerType::SERBINARY& sertype) {
    Serial::Serialize(obj, file, sertype);
}

template <typename T>
inline void SerializeToStream(std::fstream& file, const CryptoContext<T>& obj, const SerType::SERBINARY& sertype) {
    Serial::Serialize(obj, file, sertype);
}

template <typename T>
inline void DeserializeFromStream(std::fstream& file, T& obj, const SerType::SERBINARY& sertype) {
    Serial::Deserialize(obj, file, sertype);
}

template <typename T>
inline void DeserializeFromStream(std::fstream& file, CryptoContext<T>& obj, const SerType::SERBINARY& sertype) {
    Serial::Deserialize(obj, file, sertype);
}