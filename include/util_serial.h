#ifndef UTIL_SERIAL_H
#define UTIL_SERIAL_H

template <typename T>
inline void SerializeToStream(std::ofstream& file, const T& obj, const lbcrypto::SerType::SERBINARY& sertype) {
    lbcrypto::Serial::Serialize(obj, file, sertype);
}

template <typename T>
inline void SerializeToStream(std::ofstream& file, const lbcrypto::CryptoContext<T>& obj, const lbcrypto::SerType::SERBINARY& sertype) {
    lbcrypto::Serial::Serialize(obj, file, sertype);
}

template <typename T>
inline void DeserializeFromStream(std::ifstream& file, T& obj, const lbcrypto::SerType::SERBINARY& sertype) {
    lbcrypto::Serial::Deserialize(obj, file, sertype);
}

template <typename T>
inline void DeserializeFromStream(std::ifstream& file, lbcrypto::CryptoContext<T>& obj, const lbcrypto::SerType::SERBINARY& sertype) {
    lbcrypto::Serial::Deserialize(obj, file, sertype);
}

#endif